#include <bear/options.h>

struct _BearOptions {
  GObject parent_instance;

  gchar *target;
  int port;
  int send_delay_ms;
  gchar *start_vector;
  int num_packets_to_send;
  gboolean reconnect_on_disconnect;
  int reconnect_delay_ms;
  gboolean verbose;
  int max_string_length;
};

G_DEFINE_TYPE(BearOptions, bear_options, G_TYPE_OBJECT)

static void bear_options_init(BearOptions *options) {
  options->target = NULL;
  options->port = 0;
  options->send_delay_ms = 25;
  options->reconnect_on_disconnect = FALSE;
  options->reconnect_delay_ms = 5000;
  options->max_string_length = 10240;
}

void bear_options_finalize(GObject *object) {
  BearOptions *options = BEAR_OPTIONS(object);

  g_free(options->target);

  G_OBJECT_CLASS(bear_options_parent_class)->finalize(object);
}

static void bear_options_class_init(BearOptionsClass *klass) {
  G_OBJECT_CLASS(klass)->finalize = bear_options_finalize;
}

BearOptions *bear_options_new(gint argc, gchar *argv[]) {
  g_autoptr(BearOptions) options = g_object_new(BEAR_TYPE_OPTIONS, NULL);
  g_autoptr(GError) error = NULL;

  GOptionEntry entries[] = {
      {"target", 't', 0, G_OPTION_ARG_STRING, &options->target, "Target host (required)", NULL},
      {"port", 'p', 0, G_OPTION_ARG_INT, &options->port, "Target port (required)", NULL},
      {
          "send-delay-ms",
          'd',
          0,
          G_OPTION_ARG_INT,
          &options->send_delay_ms,
          "Delay in milliseconds between sending packets",
          NULL,
      },
      {"start-vector", 's', 0, G_OPTION_ARG_STRING, &options->start_vector, "Start vector", NULL},
      {"num-packets-to-send", 'n', 0, G_OPTION_ARG_INT, &options->num_packets_to_send, "Number of packets to send",
       NULL},
      {"reconnect-on-disconnect", 'c', 0, G_OPTION_ARG_NONE, &options->reconnect_on_disconnect,
       "Reconnect when remote disconnected (crashed)", NULL},
      {"reconnect-delay-ms", 'r', 0, G_OPTION_ARG_INT, &options->reconnect_delay_ms,
       "Delay in milliseconds between reconnect attempts", NULL},
      {"verbose", 'v', 0, G_OPTION_ARG_NONE, &options->verbose, "Enable verbose output", NULL},
      {"max-string-length", 'm', 0, G_OPTION_ARG_INT, &options->max_string_length, "Maximum string length", NULL},
      {NULL}};

  g_autoptr(GOptionContext) context = g_option_context_new(NULL);
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_error("Option parsing failed: %s", error->message);
    return NULL;
  }

  return g_object_ref(options);
}

const gchar *bear_options_get_target(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), NULL);
  return options->target;
}

int bear_options_get_port(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), -1);
  return options->port;
}

int bear_options_get_send_delay_ms(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), -1);
  return options->send_delay_ms;
}

const gchar *bear_options_get_start_vector(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), NULL);
  return options->start_vector;
}

int bear_options_get_num_packets_to_send(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), -1);
  return options->num_packets_to_send;
}

gboolean bear_options_reconnect_on_disconnect(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), FALSE);
  return options->reconnect_on_disconnect;
}

int bear_options_reconnect_delay_ms(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), -1);
  return options->reconnect_delay_ms;
}

gboolean bear_options_verbose(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), FALSE);
  return options->verbose;
}

int bear_options_max_string_length(BearOptions *options) {
  g_return_val_if_fail(BEAR_IS_OPTIONS(options), -1);
  return options->max_string_length;
}
