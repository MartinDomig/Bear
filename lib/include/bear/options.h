#pragma once

#if !defined(__BEAR_H_INSIDE__) && !defined(BEAR_COMPILATION)
#error "Only <bear.h> can be included directly."
#endif

#include <glib-object.h>
#include <glib.h>

G_BEGIN_DECLS

typedef struct _BearOptions BearOptions;
#define BEAR_TYPE_OPTIONS (bear_options_get_type())
G_DECLARE_FINAL_TYPE(BearOptions, bear_options, BEAR, OPTIONS, GObject)

BearOptions *bear_options_new(gint argc, gchar *argv[]);
const gchar *bear_options_get_target(BearOptions *options);
int bear_options_get_port(BearOptions *options);
int bear_options_get_send_delay_ms(BearOptions *options);

const gchar *bear_options_get_start_vector(BearOptions *options);
int bear_options_get_num_packets_to_send(BearOptions *options);
gboolean bear_options_reconnect_on_disconnect(BearOptions *options);
int bear_options_reconnect_delay_ms(BearOptions *options);
gboolean bear_options_verbose(BearOptions *options);
int bear_options_max_string_length(BearOptions *options);

G_END_DECLS
