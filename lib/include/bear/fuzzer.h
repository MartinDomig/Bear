#pragma once

#if !defined(__BEAR_H_INSIDE__) && !defined(BEAR_COMPILATION)
#error "Only <bear.h> can be included directly."
#endif

#include <glib-object.h>
#include <glib.h>

#include <bear/fuzzy-value.h>
#include <bear/options.h>

G_BEGIN_DECLS

typedef struct _BearFuzzer BearFuzzer;
#define BEAR_TYPE_FUZZER (bear_fuzzer_get_type())
G_DECLARE_FINAL_TYPE(BearFuzzer, bear_fuzzer, BEAR, FUZZER, GObject)

BearFuzzer *bear_fuzzer_new(BearOptions *options);

BearFuzzyValue *bear_fuzzer_static(BearFuzzer *fuzzer, GBytes *data);
BearFuzzyValue *bear_fuzzer_static_uint8(BearFuzzer *fuzzer, guint8 value);
BearFuzzyValue *bear_fuzzer_static_uint16(BearFuzzer *fuzzer, guint16 value);
BearFuzzyValue *bear_fuzzer_static_uint32(BearFuzzer *fuzzer, guint32 value);
BearFuzzyValue *bear_fuzzer_static_uint64(BearFuzzer *fuzzer, guint64 value);

BearFuzzyValue *bear_fuzzer_variable(BearFuzzer *fuzzer, GBytes *initial_data);
BearFuzzyValue *bear_fuzzer_variable_uint8(BearFuzzer *fuzzer, guint8 initial_value);
BearFuzzyValue *bear_fuzzer_variable_uint16(BearFuzzer *fuzzer, guint16 initial_value);
BearFuzzyValue *bear_fuzzer_variable_uint32(BearFuzzer *fuzzer, guint32 initial_value);
BearFuzzyValue *bear_fuzzer_variable_uint64(BearFuzzer *fuzzer, guint64 initial_value);

BearFuzzyValue *bear_fuzzer_static_string(BearFuzzer *fuzzer, const gchar *data);
BearFuzzyValue *bear_fuzzer_variable_string(BearFuzzer *fuzzer, const gchar *initial_value);
BearFuzzyValue *bear_fuzzer_variable_string_max(BearFuzzer *fuzzer, const gchar *initial_value, gsize max_length);

void bear_fuzzer_begin_block(BearFuzzer *fuzzer, const gchar *block_name);
void bear_fuzzer_end_block(BearFuzzer *fuzzer, const gchar *block_name);
BearFuzzyValue *bear_fuzzer_block_size(BearFuzzer *fuzzer, const gchar *block_name, gsize size_length);

typedef gboolean (*bear_fuzzer_cb)(BearFuzzer *fuzzer);
typedef gboolean (*bear_fuzzer_connection_data_cb)(BearFuzzer *fuzzer, GBytes *data);

void bear_fuzzer_on_connect(BearFuzzer *fuzzer, bear_fuzzer_cb callback);
void bear_fuzzer_on_disconnect(BearFuzzer *fuzzer, bear_fuzzer_cb callback);
void bear_fuzzer_on_send(BearFuzzer *fuzzer, bear_fuzzer_connection_data_cb callback);
void bear_fuzzer_on_receive(BearFuzzer *fuzzer, bear_fuzzer_connection_data_cb callback);

gsize bear_fuzzer_send(BearFuzzer *fuzzer, GBytes *data);

gsize bear_fuzzer_total_variability(BearFuzzer *fuzzer);
void bear_fuzzer_run(BearFuzzer *fuzzer);

gchar *bear_fuzzer_get_start_vector(BearFuzzer *fuzzer);
gchar *bear_fuzzer_get_last_vector(BearFuzzer *fuzzer);
gchar *bear_fuzzer_get_next_vector(BearFuzzer *fuzzer, const gchar *vector);
const gchar *bear_fuzzer_get_current_vector(BearFuzzer *fuzzer);
gsize *bear_fuzzer_get_vector_values(const gchar *vector, gsize *out_num_values);
GBytes *bear_fuzzer_get_data(BearFuzzer *fuzzer, const gchar *vector);

G_END_DECLS
