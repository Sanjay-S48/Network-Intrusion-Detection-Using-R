# ==============================================================
# helpers.R  --  shared constants and functions
# Project : Network Intrusion Detection Using R (+ Shiny)
# Used by : 01_analysis.R  and  app.R
# NOTE    : this file only DEFINES things; it loads no packages.
# ==============================================================

# ---- 1. NSL-KDD column names (41 features + label + difficulty) ----
nsl_cols <- c(
  "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
  "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
  "num_compromised", "root_shell", "su_attempted", "num_root",
  "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
  "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
  "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
  "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
  "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
  "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
  "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
  "dst_host_srv_rerror_rate", "label", "difficulty"
)

# ---- 2. Attack name -> attack category ----
attack_map <- c(
  normal = "normal",
  # Denial of Service
  back = "DoS", land = "DoS", neptune = "DoS", pod = "DoS", smurf = "DoS",
  teardrop = "DoS", apache2 = "DoS", udpstorm = "DoS", processtable = "DoS",
  worm = "DoS", mailbomb = "DoS",
  # Probe (scanning / surveillance)
  satan = "Probe", ipsweep = "Probe", nmap = "Probe", portsweep = "Probe",
  mscan = "Probe", saint = "Probe",
  # Remote to Local
  guess_passwd = "R2L", ftp_write = "R2L", imap = "R2L", phf = "R2L",
  multihop = "R2L", warezmaster = "R2L", warezclient = "R2L", spy = "R2L",
  xlock = "R2L", xsnoop = "R2L", snmpguess = "R2L", snmpgetattack = "R2L",
  httptunnel = "R2L", sendmail = "R2L", named = "R2L",
  # User to Root
  buffer_overflow = "U2R", loadmodule = "U2R", rootkit = "U2R", perl = "U2R",
  sqlattack = "U2R", xterm = "U2R", ps = "U2R"
)

cat_cols         <- c("protocol_type", "service", "flag")   # categorical features
log_cols         <- c("duration", "src_bytes", "dst_bytes") # heavily skewed -> log1p
non_feature_cols <- c("label", "attack_category", "class")  # targets / bookkeeping

# ---- 3. Reading and labelling data ----
finalize_nsl <- function(df) {
  df$label <- trimws(as.character(df$label))
  if ("difficulty" %in% names(df)) df$difficulty <- NULL
  df$num_outbound_cmds <- NULL                    # always 0 in NSL-KDD -> useless
  cat_vec <- unname(attack_map[df$label])
  cat_vec[is.na(cat_vec)] <- "Other"
  df$attack_category <- factor(cat_vec)
  df$class <- factor(ifelse(df$label == "normal", "normal", "attack"),
                     levels = c("normal", "attack"))
  df
}

load_nsl <- function(path) {
  df <- read.csv(path, header = FALSE, col.names = nsl_cols,
                 stringsAsFactors = FALSE)
  finalize_nsl(df)
}

# Reads a user-uploaded traffic file (with or without header row)
read_traffic_file <- function(path) {
  first <- readLines(path, n = 1, warn = FALSE)
  has_header <- grepl("duration", first, fixed = TRUE)
  df <- read.csv(path, header = has_header, stringsAsFactors = FALSE)
  if (!has_header) {
    k <- min(ncol(df), length(nsl_cols))
    names(df)[seq_len(k)] <- nsl_cols[seq_len(k)]
  }
  df
}

# ---- 4. Pre-processing (ONE code path for training AND the Shiny app) ----
mode_value <- function(x) {
  tab <- table(as.character(x))
  names(tab)[which.max(tab)]
}

# one-row data frame: median for numeric, most frequent value for categorical
make_defaults <- function(df, feat_cols) {
  out <- lapply(feat_cols, function(cc) {
    if (cc %in% cat_cols) mode_value(df[[cc]]) else median(df[[cc]], na.rm = TRUE)
  })
  names(out) <- feat_cols
  as.data.frame(out, stringsAsFactors = FALSE)
}

apply_log <- function(df) {
  for (cc in log_cols) df[[cc]] <- log1p(df[[cc]])
  df
}

prepare_for_model <- function(df, feat_cols, cat_levels, defaults) {
  for (cc in feat_cols) {
    if (!cc %in% names(df)) df[[cc]] <- defaults[[cc]]
  }
  df <- df[, feat_cols, drop = FALSE]
  for (cc in cat_cols) {
    x <- as.character(df[[cc]])
    bad <- is.na(x) | !(x %in% cat_levels[[cc]])
    x[bad] <- as.character(defaults[[cc]])
    df[[cc]] <- factor(x, levels = cat_levels[[cc]])
  }
  for (cc in setdiff(feat_cols, cat_cols)) {
    df[[cc]] <- suppressWarnings(as.numeric(df[[cc]]))
    df[[cc]][is.na(df[[cc]])] <- defaults[[cc]]
  }
  apply_log(df)
}

# ---- 5. Evaluation helpers ----
to_class <- function(prob, thr = 0.5) {
  factor(ifelse(prob > thr, "attack", "normal"), levels = c("normal", "attack"))
}

get_metrics <- function(model, truth, prob, thr = 0.5) {
  pred <- to_class(prob, thr)
  tp <- sum(pred == "attack" & truth == "attack")
  tn <- sum(pred == "normal" & truth == "normal")
  fp <- sum(pred == "attack" & truth == "normal")
  fn <- sum(pred == "normal" & truth == "attack")
  prec <- tp / (tp + fp)
  rec  <- tp / (tp + fn)
  r <- pROC::roc(response = truth, predictor = prob,
                 levels = c("normal", "attack"), direction = "<", quiet = TRUE)
  data.frame(
    Model          = model,
    Accuracy       = (tp + tn) / (tp + tn + fp + fn),
    Precision      = prec,
    Recall         = rec,
    Specificity    = tn / (tn + fp),
    F1             = 2 * prec * rec / (prec + rec),
    AUC            = as.numeric(pROC::auc(r)),
    FalseAlarmRate = fp / (fp + tn),
    stringsAsFactors = FALSE
  )
}

roc_points <- function(model, truth, prob) {
  r <- pROC::roc(response = truth, predictor = prob,
                 levels = c("normal", "attack"), direction = "<", quiet = TRUE)
  d <- data.frame(Model = model, FPR = 1 - r$specificities, TPR = r$sensitivities)
  if (nrow(d) > 600) d <- d[unique(round(seq(1, nrow(d), length.out = 600))), ]
  d
}

# ---- 6. DEMO data (ONLY for testing that the code runs; NOT real results) ----
make_demo_data <- function(n, seed) {
  set.seed(seed)
  is_att    <- runif(n) < 0.47
  stealth   <- is_att & runif(n) < 0.15          # attacks that look normal
  looks_att <- is_att & !stealth
  num_cols  <- setdiff(nsl_cols, c("protocol_type", "service", "flag", "label", "difficulty"))
  df <- as.data.frame(matrix(0, n, length(num_cols)))
  names(df) <- num_cols
  df$duration           <- rpois(n, ifelse(looks_att, 1, 20))
  df$src_bytes          <- ifelse(looks_att, rpois(n, 5), rpois(n, 800))
  df$dst_bytes          <- ifelse(looks_att, 0, rpois(n, 3000))
  df$logged_in          <- as.integer(!looks_att & runif(n) < 0.9)
  df$count              <- ifelse(looks_att, pmin(511, rpois(n, 200)), rpois(n, 8))
  df$srv_count          <- ifelse(looks_att, rpois(n, 15), rpois(n, 8))
  df$serror_rate        <- ifelse(looks_att & runif(n) < 0.7, 1, runif(n) * 0.1)
  df$rerror_rate        <- ifelse(looks_att & runif(n) < 0.2, 1, runif(n) * 0.05)
  df$same_srv_rate      <- ifelse(looks_att, runif(n) * 0.3, 0.8 + runif(n) * 0.2)
  df$dst_host_count     <- ifelse(looks_att, 255, pmin(255, rpois(n, 60)))
  df$dst_host_srv_count <- ifelse(looks_att, rpois(n, 12), pmin(255, rpois(n, 150)))
  df$dst_host_serror_rate <- ifelse(looks_att & runif(n) < 0.7, 1, runif(n) * 0.1)
  df$hot                <- rpois(n, 0.3)
  df$protocol_type <- sample(c("tcp", "udp", "icmp"), n, TRUE, prob = c(.6, .25, .15))
  df$service <- sample(c("http", "ftp_data", "private", "smtp", "domain_u", "ecr_i", "other"), n, TRUE)
  df$flag <- ifelse(looks_att,
                    sample(c("S0", "REJ", "SF"), n, TRUE, prob = c(.55, .30, .15)),
                    sample(c("SF", "S0", "REJ"), n, TRUE, prob = c(.90, .05, .05)))
  df$label <- ifelse(is_att,
                     sample(c("neptune", "smurf", "satan", "ipsweep", "guess_passwd", "buffer_overflow"),
                            n, TRUE, prob = c(.45, .20, .15, .10, .07, .03)),
                     "normal")
  df$difficulty <- 15
  finalize_nsl(df[, nsl_cols])
}
