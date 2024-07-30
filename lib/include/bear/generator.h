#pragma once

#if !defined(__BEAR_H_INSIDE__) && !defined(BEAR_COMPILATION)
#error "Only <bear.h> can be included directly."
#endif

#include <bear/fuzzy-value.h>

#include <glib-object.h>
#include <glib.h>

G_BEGIN_DECLS

typedef struct _BearGenerator BearGenerator;
#define BEAR_TYPE_GENERATOR (bear_generator_get_type())
G_DECLARE_FINAL_TYPE(BearGenerator, bear_generator, BEAR, GENERATOR, GObject)

BearGenerator *bear_generator_new(GList *values);

gboolean bear_generator_validate_vector(BearGenerator *generator, const gchar *vector);
gboolean bear_generator_set_vector(BearGenerator *generator, const gchar *vector);
const gchar *bear_generator_get_current_vector(BearGenerator *generator);
const gchar *bear_generator_get_start_vector(BearGenerator *generator);
const gchar *bear_generator_increment_vector(BearGenerator *generator);
const gchar *bear_generator_get_last_vector(BearGenerator *fuzzer);

GArray *bear_generator_get_vector_values(const gchar *vector);
const GArray *bear_generator_get_variabilities(BearGenerator *generator);
gsize bear_generator_total_variability(BearGenerator *generator);

GBytes *bear_generator_get_data(BearGenerator *generator, const gchar *vector);

G_END_DECLS
