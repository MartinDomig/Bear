#pragma once

#if !defined(__BEAR_H_INSIDE__) && !defined(BEAR_COMPILATION)
#error "Only <bear.h> can be included directly."
#endif

#include <glib-object.h>
#include <glib.h>

G_BEGIN_DECLS

typedef struct _BearFuzzyValue BearFuzzyValue;
#define BEAR_TYPE_FUZZY_VALUE (bear_fuzzy_value_get_type())
G_DECLARE_FINAL_TYPE(BearFuzzyValue, bear_fuzzy_value, BEAR, FUZZY_VALUE, GObject)

BearFuzzyValue *bear_fuzzy_value_new_static(GBytes *data);
BearFuzzyValue *bear_fuzzy_value_new_static_string(const gchar *value);
BearFuzzyValue *bear_fuzzy_value_new_variable(GBytes *data);
BearFuzzyValue *bear_fuzzy_value_new_variable_string(const gchar *initial_value);
void bear_fuzzy_value_set_strings(BearFuzzyValue *value, ...);

BearFuzzyValue *bear_fuzzy_value_new_sizeof_block(const gchar *block_name, gsize integer_size);

void bear_fuzzy_value_set_max_string_length(BearFuzzyValue *value, gsize max_length);
gsize bear_fuzzy_value_get_max_string_length(BearFuzzyValue *value);

gsize bear_fuzzy_value_size(BearFuzzyValue *value, GList *all_values, gsize variability);
gsize bear_fuzzy_value_variability(BearFuzzyValue *value);
void bear_fuzzy_value_set_block(BearFuzzyValue *value, const gchar *block_name);
GBytes *bear_fuzzy_value_generate(BearFuzzyValue *value, GList *all_values, gsize variability);

G_END_DECLS
