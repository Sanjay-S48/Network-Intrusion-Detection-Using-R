# ==============================================================
# app.R  --  Shiny dashboard : Network Intrusion Detection System
# Run 01_analysis.R first (it creates outputs/ids_bundle.rds), then:
#   shiny::runApp()
# ==============================================================

library(shiny)
library(ggplot2)
library(DT)
library(ranger)
source("R/helpers.R")

bundle_path <- "outputs/ids_bundle.rds"
if (!file.exists(bundle_path)) {
  stop("outputs/ids_bundle.rds not found. Run source('01_analysis.R') first.")
}
bundle <- readRDS(bundle_path)

COLS <- c(normal = "#14B8A6", attack = "#E5484D")
num_feats <- setdiff(bundle$feat_cols, cat_cols)

predict_prob <- function(raw_df) {
  x <- prepare_for_model(raw_df, bundle$feat_cols, bundle$cat_levels, bundle$defaults)
  predict(bundle$rf_model, data = x)$predictions[, "attack"]
}

# inputs used in the "Live Detection" tab
live_cat <- c("protocol_type", "service", "flag")
live_num <- c("duration", "src_bytes", "dst_bytes", "logged_in", "count", "srv_count",
              "serror_rate", "rerror_rate", "same_srv_rate", "dst_host_count",
              "dst_host_srv_count", "dst_host_serror_rate")
d <- bundle$defaults

presets <- list(
  normal = list(protocol_type = "tcp", service = "http", flag = "SF", duration = 0,
                src_bytes = 232, dst_bytes = 8153, logged_in = 1, count = 5, srv_count = 5,
                serror_rate = 0, rerror_rate = 0, same_srv_rate = 1, dst_host_count = 30,
                dst_host_srv_count = 255, dst_host_serror_rate = 0),
  syn_flood = list(protocol_type = "tcp", service = "private", flag = "S0", duration = 0,
                   src_bytes = 0, dst_bytes = 0, logged_in = 0, count = 250, srv_count = 20,
                   serror_rate = 1, rerror_rate = 0, same_srv_rate = 0.08, dst_host_count = 255,
                   dst_host_srv_count = 15, dst_host_serror_rate = 1),
  port_scan = list(protocol_type = "tcp", service = "private", flag = "REJ", duration = 0,
                   src_bytes = 0, dst_bytes = 0, logged_in = 0, count = 150, srv_count = 8,
                   serror_rate = 0, rerror_rate = 1, same_srv_rate = 0.05, dst_host_count = 255,
                   dst_host_srv_count = 10, dst_host_serror_rate = 0)
)

verdict_ui <- function(p, thr) {
  is_att <- p > thr
  col <- if (is_att) COLS[["attack"]] else COLS[["normal"]]
  tags$div(
    style = paste0("border:2px solid ", col, ";border-radius:10px;padding:16px;margin-top:10px;"),
    tags$h3(style = paste0("color:", col, ";margin-top:0;"),
            if (is_att) "ALERT: possible intrusion" else "Traffic looks normal"),
    tags$p(sprintf("Attack probability: %.1f%%", p * 100)),
    tags$div(style = "background:#E2E8F0;border-radius:6px;height:16px;",
             tags$div(style = paste0("background:", col, ";height:16px;border-radius:6px;width:",
                                     round(p * 100), "%;")))
  )
}

theme_ids <- theme_minimal(base_size = 13)

# ----------------------------- UI -----------------------------
ui <- navbarPage(
  "Network Intrusion Detection System (R + Shiny)",

  tabPanel("Overview",
    uiOutput("demo_banner"),
    fluidRow(
      column(3, wellPanel(h2(textOutput("n_train")), p("training connections"))),
      column(3, wellPanel(h2(textOutput("n_test")),  p("test connections"))),
      column(3, wellPanel(h2(textOutput("n_feat")),  p("input features"))),
      column(3, wellPanel(h2(textOutput("best_model")), p("best F1 model")))
    ),
    fluidRow(
      column(6, plotOutput("ov_class")),
      column(6, plotOutput("ov_cat"))
    ),
    p("This dashboard explores the NSL-KDD dataset, compares three machine-learning models and
       lets you test network connections for intrusions.")
  ),

  tabPanel("Data Explorer",
    sidebarLayout(
      sidebarPanel(
        selectInput("feat", "Numeric feature", choices = num_feats, selected = "src_bytes"),
        checkboxInput("logx", "Use log(1 + x) scale", TRUE),
        selectInput("cat_feat", "Categorical feature", c("protocol_type", "flag", "attack_category"))
      ),
      mainPanel(plotOutput("hist"), plotOutput("catplot"),
                h4("Sample of the training data"), DTOutput("tbl"))
    )
  ),

  tabPanel("Model Performance",
    h4("Metrics on the test set"), DTOutput("metrics_tbl"),
    fluidRow(column(6, plotOutput("metric_bar")), column(6, plotOutput("roc_plot"))),
    fluidRow(
      column(6, selectInput("cm_model", "Confusion matrix of:", names(bundle$cm_list),
                            selected = "Random Forest"), plotOutput("cm_plot")),
      column(6, br(), br(), plotOutput("imp_plot"))
    ),
    fluidRow(column(8, h4("Attack-category prediction (multi-class Random Forest)"),
                    textOutput("mc_acc"), plotOutput("mc_plot")))
  ),

  tabPanel("Live Detection",
    sidebarLayout(
      sidebarPanel(
        h4("Describe one network connection"),
        actionButton("p_norm", "Example: normal web"),
        actionButton("p_syn",  "Example: SYN flood"),
        actionButton("p_scan", "Example: port scan"),
        hr(),
        selectInput("protocol_type", "protocol_type", bundle$cat_levels$protocol_type, d$protocol_type),
        selectInput("service", "service", bundle$cat_levels$service, d$service),
        selectInput("flag", "flag", bundle$cat_levels$flag, d$flag),
        numericInput("duration", "duration (s)", d$duration, min = 0),
        numericInput("src_bytes", "src_bytes", d$src_bytes, min = 0),
        numericInput("dst_bytes", "dst_bytes", d$dst_bytes, min = 0),
        numericInput("logged_in", "logged_in (0/1)", d$logged_in, min = 0, max = 1),
        numericInput("count", "count (connections to same host)", d$count, min = 0),
        numericInput("srv_count", "srv_count (same service)", d$srv_count, min = 0),
        numericInput("serror_rate", "serror_rate (0-1)", d$serror_rate, min = 0, max = 1, step = 0.05),
        numericInput("rerror_rate", "rerror_rate (0-1)", d$rerror_rate, min = 0, max = 1, step = 0.05),
        numericInput("same_srv_rate", "same_srv_rate (0-1)", d$same_srv_rate, min = 0, max = 1, step = 0.05),
        numericInput("dst_host_count", "dst_host_count", d$dst_host_count, min = 0),
        numericInput("dst_host_srv_count", "dst_host_srv_count", d$dst_host_srv_count, min = 0),
        numericInput("dst_host_serror_rate", "dst_host_serror_rate (0-1)", d$dst_host_serror_rate,
                     min = 0, max = 1, step = 0.05),
        sliderInput("thr_live", "Alert threshold", 0.05, 0.95, 0.5, 0.05),
        actionButton("go_live", "Detect", class = "btn-primary")
      ),
      mainPanel(
        uiOutput("live_result"),
        p("Features not shown here are filled with typical (median / most frequent) values
           from the training data.")
      )
    )
  ),

  tabPanel("Batch Detection",
    sidebarLayout(
      sidebarPanel(
        fileInput("upload", "Upload a CSV / TXT of connections", accept = c(".csv", ".txt")),
        p("Use NSL-KDD format (with or without header). A ready sample is created at
           outputs/sample_upload_test.csv"),
        sliderInput("thr_batch", "Alert threshold", 0.05, 0.95, 0.5, 0.05),
        downloadButton("dl", "Download results")
      ),
      mainPanel(textOutput("batch_summary"), plotOutput("batch_plot"), DTOutput("batch_tbl"))
    )
  ),

  tabPanel("About",
    h3("About this project"),
    p("R Mini Project - Network Intrusion Detection using machine learning in R."),
    tags$ul(
      tags$li("Dataset: NSL-KDD (KDDTrain+ / KDDTest+)"),
      tags$li("Models: Logistic Regression, Decision Tree, Random Forest (ranger)"),
      tags$li("Interface: Shiny"),
      tags$li("Live Detection uses the Random Forest model.")
    ),
    p("Educational project - not a replacement for a production IDS.")
  )
)

# --------------------------- SERVER ---------------------------
server <- function(input, output, session) {

  output$demo_banner <- renderUI({
    if (isTRUE(bundle$demo_mode)) {
      tags$div(style = "background:#FEF3C7;padding:10px;border-radius:6px;margin-bottom:10px;",
               "DEMO MODE: this app was trained on synthetic data, not NSL-KDD.")
    }
  })

  # ---- Overview ----
  output$n_train <- renderText(format(bundle$n_train, big.mark = ","))
  output$n_test  <- renderText(format(bundle$n_test,  big.mark = ","))
  output$n_feat  <- renderText(length(bundle$feat_cols))
  output$best_model <- renderText(bundle$metrics$Model[which.max(bundle$metrics$F1)])

  output$ov_class <- renderPlot({
    df <- bundle$train_class; names(df) <- c("class", "n")
    ggplot(df, aes(class, n, fill = class)) + geom_col() +
      scale_fill_manual(values = COLS) + labs(title = "Normal vs attack", x = NULL, y = "Count") +
      theme_ids + theme(legend.position = "none")
  })
  output$ov_cat <- renderPlot({
    df <- bundle$train_cat; names(df) <- c("category", "n")
    df <- df[df$n > 0, ]
    ggplot(df, aes(category, n, fill = category)) + geom_col() + scale_y_log10() +
      labs(title = "Attack categories (log scale)", x = NULL, y = "Count") +
      theme_ids + theme(legend.position = "none")
  })

  # ---- Data Explorer ----
  output$hist <- renderPlot({
    df <- bundle$eda_sample
    x <- df[[input$feat]]
    if (input$logx) x <- log1p(x)
    pd <- data.frame(x = x, class = df$class)
    ggplot(pd, aes(x, fill = class)) + geom_histogram(bins = 40, alpha = 0.7, position = "identity") +
      scale_fill_manual(values = COLS) +
      labs(title = paste("Distribution of", input$feat), x = input$feat, y = "Count") + theme_ids
  })
  output$catplot <- renderPlot({
    df <- bundle$eda_sample
    pd <- data.frame(v = as.character(df[[input$cat_feat]]), class = df$class)
    ggplot(pd, aes(v, fill = class)) + geom_bar(position = "dodge") +
      scale_fill_manual(values = COLS) +
      labs(title = paste(input$cat_feat, "vs class"), x = NULL, y = "Count") + theme_ids
  })
  output$tbl <- renderDT(datatable(bundle$eda_sample[1:200, ], options = list(scrollX = TRUE, pageLength = 5)))

  # ---- Model performance ----
  output$metrics_tbl <- renderDT(datatable(bundle$metrics, rownames = FALSE,
                                           options = list(dom = "t")))
  output$metric_bar <- renderPlot({
    m <- bundle$metrics
    ml <- data.frame(Model = rep(m$Model, 4),
                     Metric = rep(c("Accuracy", "Precision", "Recall", "F1"), each = nrow(m)),
                     Value = c(m$Accuracy, m$Precision, m$Recall, m$F1))
    ggplot(ml, aes(Metric, Value, fill = Model)) + geom_col(position = "dodge") +
      coord_cartesian(ylim = c(0, 1)) + labs(title = "Model comparison", x = NULL, y = NULL) + theme_ids
  })
  output$roc_plot <- renderPlot({
    ggplot(bundle$roc_df, aes(FPR, TPR, colour = Model)) + geom_line(linewidth = 1) +
      geom_abline(linetype = "dashed", colour = "grey50") + labs(title = "ROC curves") + theme_ids
  })
  output$cm_plot <- renderPlot({
    cm <- bundle$cm_list[[input$cm_model]]
    ggplot(cm, aes(Actual, Predicted, fill = Freq)) + geom_tile() +
      geom_text(aes(label = Freq), size = 6) +
      scale_fill_gradient(low = "#F1F5F9", high = "#14B8A6") +
      labs(title = paste("Confusion matrix -", input$cm_model)) + theme_ids
  })
  output$imp_plot <- renderPlot({
    imp <- bundle$importance[1:15, ]
    imp$Feature <- factor(imp$Feature, levels = rev(imp$Feature))
    ggplot(imp, aes(Feature, Importance)) + geom_col(fill = "#14B8A6") + coord_flip() +
      labs(title = "Top 15 features (Random Forest)", x = NULL) + theme_ids
  })
  output$mc_acc <- renderText(sprintf("Overall multi-class accuracy: %.2f%%", bundle$mc_accuracy * 100))
  output$mc_plot <- renderPlot({
    ggplot(bundle$mc_cm, aes(Actual, Predicted, fill = Freq)) + geom_tile() +
      geom_text(aes(label = Freq), size = 4) +
      scale_fill_gradient(low = "#F1F5F9", high = "#E5484D") + theme_ids
  })

  # ---- Live detection ----
  set_inputs <- function(p) {
    for (nm in live_cat) {
      if (p[[nm]] %in% bundle$cat_levels[[nm]]) updateSelectInput(session, nm, selected = p[[nm]])
    }
    for (nm in live_num) updateNumericInput(session, nm, value = p[[nm]])
  }
  observeEvent(input$p_norm, set_inputs(presets$normal))
  observeEvent(input$p_syn,  set_inputs(presets$syn_flood))
  observeEvent(input$p_scan, set_inputs(presets$port_scan))

  live_p <- eventReactive(input$go_live, {
    row <- bundle$defaults
    for (nm in c(live_cat, live_num)) row[[nm]] <- input[[nm]]
    predict_prob(row)
  })
  output$live_result <- renderUI({
    req(live_p())
    verdict_ui(live_p(), input$thr_live)
  })

  # ---- Batch detection ----
  batch_res <- reactive({
    req(input$upload)
    df <- read_traffic_file(input$upload$datapath)
    p <- predict_prob(df)
    out <- data.frame(row = seq_len(nrow(df)), attack_probability = round(p, 4))
    out$verdict <- ifelse(p > input$thr_batch, "attack", "normal")
    if ("label" %in% names(df)) out$actual_label <- df$label
    out
  })
  output$batch_summary <- renderText({
    r <- batch_res()
    sprintf("%d connections scanned: %d flagged as attacks (%.1f%%)",
            nrow(r), sum(r$verdict == "attack"), 100 * mean(r$verdict == "attack"))
  })
  output$batch_plot <- renderPlot({
    r <- batch_res()
    ggplot(r, aes(attack_probability, fill = verdict)) + geom_histogram(bins = 30) +
      scale_fill_manual(values = COLS) + labs(title = "Predicted attack probability", x = NULL) + theme_ids
  })
  output$batch_tbl <- renderDT(datatable(batch_res(), options = list(pageLength = 10)))
  output$dl <- downloadHandler(
    filename = function() "ids_predictions.csv",
    content  = function(file) write.csv(batch_res(), file, row.names = FALSE)
  )
}

shinyApp(ui, server)
