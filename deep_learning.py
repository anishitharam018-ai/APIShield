"""Autoencoder anomaly model and the combined connection score."""
import numpy as np

from rules import (COMMON_PORTS, LOLBINS, REMOTE_ACCESS_PORTS, SYSROOT, SYSTEM_NAMES,
                   in_suspicious_dir, ip_kind, norm, rule_score_connection)


# ----------------------------------------------------------- deep learning --
# A tiny autoencoder neural network, written with plain NumPy so the agent
# does not need PyTorch/TensorFlow. It has no fixed idea of "bad" traffic:
# it is trained continuously, one connection at a time, only on what THIS
# computer actually does. A well-behaved connection looks like ones the
# network has already learned, so the network reconstructs its feature
# vector accurately (low error). A connection that does not match the
# pattern the network has learned - a new destination, an odd port, a
# process behaving unlike itself - reconstructs badly (high error). That
# reconstruction error, turned into a 0-1 score, is the model's anomaly
# score. This is the same technique ("autoencoder anomaly detection") used
# in production network-security products, just sized down to run on a
# laptop with no GPU and no external services.

DL_FEATURE_NAMES = (
    "destination is a public IP", "destination is a private IP",
    "program runs from a suspicious folder", "system-named but outside the Windows folder",
    "program is a scripting/LOLBin tool", "remote port (scaled)", "remote port is a common one",
    "how many connections this program has open (scaled)", "remote-access port (RDP/VNC/etc.)",
)
DL_N_FEATURES = len(DL_FEATURE_NAMES)


def dl_featurize(proc, ip, port, proc_conns):
    """Turns one connection into the numeric feature vector the network sees."""
    kind = ip_kind(ip)
    name = (proc.get("name") or "").lower()
    exe = proc.get("exe") or ""
    sysname_mismatch = name in SYSTEM_NAMES and bool(exe) and not norm(exe).startswith(SYSROOT)
    return np.array([
        1.0 if kind == "public" else 0.0,
        1.0 if kind == "private" else 0.0,
        1.0 if in_suspicious_dir(exe) else 0.0,
        1.0 if sysname_mismatch else 0.0,
        1.0 if name in LOLBINS else 0.0,
        min(port, 65535) / 65535.0,
        1.0 if port in COMMON_PORTS else 0.0,
        min(np.log1p(max(proc_conns, 0)) / 6.0, 1.0),
        1.0 if port in REMOTE_ACCESS_PORTS else 0.0,
    ], dtype=np.float64)


class Autoencoder:
    """Feed-forward autoencoder (N -> hidden -> N) trained online by plain
    gradient descent, one sample at a time. No batches, no saved checkpoints,
    no data leaving this process: it starts from random weights every run
    and learns this machine's traffic as it goes."""

    def __init__(self, n_in=DL_N_FEATURES, n_hidden=5, lr=0.05, warmup=40, seed=None):
        rng = np.random.default_rng(seed)
        self.W1 = rng.normal(0.0, np.sqrt(2.0 / n_in), (n_in, n_hidden))
        self.b1 = np.zeros(n_hidden)
        self.W2 = rng.normal(0.0, np.sqrt(2.0 / n_hidden), (n_hidden, n_in))
        self.b2 = np.zeros(n_in)
        self.lr = lr
        self.n_seen = 0
        self.warmup = warmup          # samples to learn from before it starts flagging anything
        self.err_mean = 0.0           # running mean of reconstruction error (MSE)
        self.err_var = 1e-4           # running variance of reconstruction error

    def _forward(self, x):
        h = np.tanh(x @ self.W1 + self.b1)
        out = h @ self.W2 + self.b2
        return h, out

    def observe(self, x):
        """Trains on x (one gradient step) and returns (score 0..1, raw MSE)."""
        h, out = self._forward(x)
        err = out - x
        mse = float(np.mean(err ** 2))

        # backprop for a squared-error loss through a tanh hidden layer
        d_out = (2.0 / x.shape[0]) * err
        gW2 = np.outer(h, d_out)
        gb2 = d_out
        d_h = d_out @ self.W2.T
        d_z1 = d_h * (1.0 - h ** 2)
        gW1 = np.outer(x, d_z1)
        gb1 = d_z1
        self.W2 -= self.lr * gW2
        self.b2 -= self.lr * gb2
        self.W1 -= self.lr * gW1
        self.b1 -= self.lr * gb1

        self.n_seen += 1
        alpha = 1.0 / self.n_seen if self.n_seen <= 50 else 0.02  # settles into an EMA
        delta = mse - self.err_mean
        self.err_mean += alpha * delta
        self.err_var = max((1.0 - alpha) * (self.err_var + alpha * delta * delta), 1e-6)

        if self.n_seen < self.warmup:
            return 0.05, mse  # still learning what "normal" looks like on this machine
        z = (mse - self.err_mean) / (self.err_var ** 0.5)     # how many std-devs above normal
        score = 1.0 / (1.0 + np.exp(-1.4 * (z - 1.5)))         # squashed to 0..1
        return float(score), mse


def score_connection(dl, proc, ip, port, proc_conns):
    """Combines the deep-learning model's anomaly score with the rule-based
    score, and returns (score 0..1, list of reasons) for display."""
    rule_score, reasons = rule_score_connection(proc, ip, port, proc_conns)
    x = dl_featurize(proc, ip, port, proc_conns)
    dl_score, dl_mse = dl.observe(x)

    if dl.n_seen < dl.warmup:
        reasons.append("The deep-learning model is still learning this computer's normal traffic (%d/%d connections seen)"
                        % (dl.n_seen, dl.warmup))
    elif dl_score >= 0.5:
        reasons.append("The deep-learning model finds this connection's pattern unlike this computer's normal traffic "
                        "(reconstruction error %.3f)" % dl_mse)

    final = round(min(max(rule_score, dl_score), 0.99), 2)
    if not reasons:
        reasons.append("Matches normal behaviour: usual location, destination and port, and the deep-learning model "
                        "reconstructs it well")
    return final, reasons
