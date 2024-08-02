#include <bear/fuzzer.h>
#include <bear/generator.h>
#include <bear/options.h>
#include <bear/tools.h>

#include <gio/gio.h>
#include <glib-unix.h>
#include <sys/socket.h>

struct _BearFuzzer {
    GObject parent_instance;

    GMainLoop *loop;
    BearOptions *options;
    bear_fuzzer_cb on_connect;
    bear_fuzzer_data_cb on_disconnect;
    bear_fuzzer_cb on_timeout;
    bear_fuzzer_data_cb on_receive;

    GList *values;

    GSocketClient *client;
    GSocketConnection *connection;
    GInputStream *input_stream;
    GOutputStream *output_stream;
    GSource *source;
    gboolean connected;
    GList *block_stack;

    BearGenerator *generator;

    GBytes *current_data;
    gchar *current_vector;
    gint num_packets;
    gsize packet_seq;
    guint receive_timeout_handle;
    guint send_next_packet_handle;
};

G_DEFINE_TYPE(BearFuzzer, bear_fuzzer, G_TYPE_OBJECT)

static void bear_fuzzer_init(BearFuzzer *fuzzer) {}

static void bear_fuzzer_dispose(GObject *object) {
    BearFuzzer *fuzzer = BEAR_FUZZER(object);
    g_list_free_full(fuzzer->values, g_object_unref);
    fuzzer->values = NULL;
    g_list_free_full(fuzzer->block_stack, g_free);
    fuzzer->block_stack = NULL;
    G_OBJECT_CLASS(bear_fuzzer_parent_class)->dispose(object);
}

void bear_fuzzer_finalize(GObject *object) {
    BearFuzzer *fuzzer = BEAR_FUZZER(object);
    g_clear_object(&fuzzer->connection);
    g_clear_object(&fuzzer->client);
    g_clear_object(&fuzzer->options);
    g_clear_object(&fuzzer->generator);
    g_free(fuzzer->current_vector);
    g_bytes_unref(fuzzer->current_data);
    G_OBJECT_CLASS(bear_fuzzer_parent_class)->finalize(object);
}

static void bear_fuzzer_class_init(BearFuzzerClass *klass) {
    G_OBJECT_CLASS(klass)->dispose = bear_fuzzer_dispose;
    G_OBJECT_CLASS(klass)->finalize = bear_fuzzer_finalize;
}

BearFuzzer *bear_fuzzer_new(BearOptions *options) {
    g_return_val_if_fail(options == NULL || BEAR_IS_OPTIONS(options), NULL);

    BearFuzzer *fuzzer = g_object_new(BEAR_TYPE_FUZZER, NULL);
    if (options != NULL) {
        fuzzer->options = g_object_ref(options);
    } else {
        fuzzer->options = bear_options_new(0, NULL);
    }

    return fuzzer;
}

static gchar *bear_fuzzer_block_stack(BearFuzzer *fuzzer) {
    GString *stack = g_string_new("");
    for (GList *iterator = fuzzer->block_stack; iterator; iterator = iterator->next) {
        if (stack->len > 0)
            g_string_append_c(stack, '.');
        g_string_append_printf(stack, "%s", (gchar *)iterator->data);
    }
    return g_string_free(stack, FALSE);
}

static BearFuzzyValue *bear_fuzzer_add_value(BearFuzzer *fuzzer, BearFuzzyValue *value) {
    g_return_val_if_fail(fuzzer->generator == NULL, NULL);

    g_autofree gchar *block = bear_fuzzer_block_stack(fuzzer);
    bear_fuzzy_value_set_block(value, block);
    bear_fuzzy_value_set_max_string_length(value, bear_options_max_string_length(fuzzer->options));
    fuzzer->values = g_list_append(fuzzer->values, value);
    return value;
}

BearFuzzyValue *bear_fuzzer_static(BearFuzzer *fuzzer, GBytes *data) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), 0);
    return bear_fuzzer_add_value(fuzzer, bear_fuzzy_value_new_static(data));
}

BearFuzzyValue *bear_fuzzer_static_uint8(BearFuzzer *fuzzer, guint8 value) {
    g_autoptr(GBytes) data = g_bytes_new(&value, sizeof(value));
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_static_uint16(BearFuzzer *fuzzer, guint16 value) {
    guint16 network_value = GUINT16_TO_BE(value);
    g_autoptr(GBytes) data = g_bytes_new(&network_value, sizeof(value));
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_static_uint32(BearFuzzer *fuzzer, guint32 value) {
    guint32 network_value = GUINT32_TO_BE(value);
    g_autoptr(GBytes) data = g_bytes_new(&network_value, sizeof(value));
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_static_uint64(BearFuzzer *fuzzer, guint64 value) {
    guint64 network_value = GUINT64_TO_BE(value);
    g_autoptr(GBytes) data = g_bytes_new(&network_value, sizeof(value));
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_static_string(BearFuzzer *fuzzer, const gchar *string) {
    g_autoptr(GBytes) data = g_bytes_new(string, strlen(string));
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_static_hex(BearFuzzer *fuzzer, const gchar *hex) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), NULL);
    g_autoptr(GBytes) data = bear_tools_hex_to_bytes(hex);
    g_autofree gchar *hex_str = bear_tools_bytes_to_hex(data);
    g_print("Hex: %s\n", hex_str);
    g_return_val_if_fail(data != NULL, NULL);
    return bear_fuzzer_static(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_variable(BearFuzzer *fuzzer, GBytes *data) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), 0);
    return bear_fuzzer_add_value(fuzzer, bear_fuzzy_value_new_variable(data));
}

BearFuzzyValue *bear_fuzzer_variable_hex(BearFuzzer *fuzzer, const gchar *hex) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), NULL);
    g_autoptr(GBytes) data = bear_tools_hex_to_bytes(hex);
    g_return_val_if_fail(data != NULL, NULL);
    return bear_fuzzer_add_value(fuzzer, bear_fuzzy_value_new_variable(data));
}

BearFuzzyValue *bear_fuzzer_variable_uint8(BearFuzzer *fuzzer, guint8 initial_value) {
    g_autoptr(GBytes) data = g_bytes_new(&initial_value, sizeof(initial_value));
    return bear_fuzzer_variable(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_variable_uint16(BearFuzzer *fuzzer, guint16 initial_value) {
    g_autoptr(GBytes) data = g_bytes_new(&initial_value, sizeof(initial_value));
    return bear_fuzzer_variable(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_variable_uint32(BearFuzzer *fuzzer, guint32 initial_value) {
    g_autoptr(GBytes) data = g_bytes_new(&initial_value, sizeof(initial_value));
    return bear_fuzzer_variable(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_variable_uint64(BearFuzzer *fuzzer, guint64 initial_value) {
    g_autoptr(GBytes) data = g_bytes_new(&initial_value, sizeof(initial_value));
    return bear_fuzzer_variable(fuzzer, data);
}

BearFuzzyValue *bear_fuzzer_variable_string(BearFuzzer *fuzzer, const gchar *initial_value) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), 0);
    return bear_fuzzer_add_value(fuzzer, bear_fuzzy_value_new_variable_string(initial_value));
}

BearFuzzyValue *bear_fuzzer_variable_string_max(BearFuzzer *fuzzer, const gchar *initial_value, gsize max_length) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), 0);
    BearFuzzyValue *v = bear_fuzzy_value_new_variable_string(initial_value);
    bear_fuzzy_value_set_max_string_length(v, max_length);
    return bear_fuzzer_add_value(fuzzer, v);
}

void bear_fuzzer_begin_block(BearFuzzer *fuzzer, const gchar *block_name) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    fuzzer->block_stack = g_list_append(fuzzer->block_stack, g_strdup(block_name));
}

void bear_fuzzer_end_block(BearFuzzer *fuzzer, const gchar *block_name) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    g_return_if_fail(fuzzer->block_stack != NULL);

    g_autofree gchar *name = g_list_last(fuzzer->block_stack)->data;
    if (g_strcmp0(name, block_name) != 0) {
        g_warning("Block mismatch: expected %s, got %s", name, block_name);
        return;
    }

    fuzzer->block_stack = g_list_remove(fuzzer->block_stack, name);
}

BearFuzzyValue *bear_fuzzer_block_size(BearFuzzer *fuzzer, const gchar *block_name, gsize size_length) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), 0);

    g_autofree gchar *tmp_name = g_strdup(block_name);
    if (fuzzer->block_stack) {
        g_autofree gchar *prefix = bear_fuzzer_block_stack(fuzzer);
        g_free(tmp_name);
        tmp_name = g_strdup_printf("%s.%s", prefix, block_name);
    }

    BearFuzzyValue *value = bear_fuzzy_value_new_sizeof_block(tmp_name, size_length);
    return bear_fuzzer_add_value(fuzzer, value);
}

void bear_fuzzer_on_connect(BearFuzzer *fuzzer, bear_fuzzer_cb callback) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    fuzzer->on_connect = callback;
}

void bear_fuzzer_on_disconnect(BearFuzzer *fuzzer, bear_fuzzer_data_cb callback) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    fuzzer->on_disconnect = callback;
}

void bear_fuzzer_on_receive(BearFuzzer *fuzzer, bear_fuzzer_data_cb callback) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    fuzzer->on_receive = callback;
}

static gboolean bear_fuzzer_connect(gpointer user_data);
static gboolean send_next_packet(gpointer user_data);
static gboolean receive_timeout_handler(gpointer user_data);

static void schedule_next_packet(BearFuzzer *fuzzer) {
    if (fuzzer->send_next_packet_handle) {
        g_source_remove(fuzzer->send_next_packet_handle);
        fuzzer->send_next_packet_handle = 0;
    }
    fuzzer->send_next_packet_handle = g_idle_add(send_next_packet, fuzzer);
}

static gboolean receive_timeout_handler(gpointer user_data) {
    BearFuzzer *fuzzer = BEAR_FUZZER(user_data);

    fuzzer->receive_timeout_handle = 0;
    g_message("Receive timeout @%s", fuzzer->current_vector);
    if (fuzzer->on_timeout)
        fuzzer->on_timeout(fuzzer, fuzzer->current_vector);
    schedule_next_packet(fuzzer);
    return G_SOURCE_REMOVE;
}

static gboolean bear_fuzzer_connection_callback(GInputStream *source, BearFuzzer *fuzzer) {
    gboolean wait_for_data = TRUE;
    int delay_ms = bear_options_get_receive_delay_ms(fuzzer->options);

    if (fuzzer->receive_timeout_handle) {
        g_source_remove(fuzzer->receive_timeout_handle);
        fuzzer->receive_timeout_handle = 0;
    }

    while (wait_for_data) {
        usleep(delay_ms * 1000);
        g_autoptr(GByteArray) byte_array = g_byte_array_new();

        guint8 buffer[1024];
        gssize bytes_available = 0;
        do {
            g_autoptr(GError) error = NULL;

            usleep(50 * 1000);
            bytes_available = g_pollable_input_stream_read_nonblocking(G_POLLABLE_INPUT_STREAM(fuzzer->input_stream), buffer,
                                                                       sizeof(buffer), NULL, &error);

            // when the remote side closes the connection, we will get a read event
            // but no data will be available
            if (error || (bytes_available == 0 && byte_array->len == 0)) {
                if (error)
                    g_message("Error reading from input stream @%s (%s)", fuzzer->current_vector, error->message);
                else
                    g_message("Remote closed connection @%s", fuzzer->current_vector);

                fuzzer->connected = FALSE;
                gboolean should_reconnect = bear_options_reconnect_on_disconnect(fuzzer->options);
                if (fuzzer->on_disconnect)
                    should_reconnect &= fuzzer->on_disconnect(fuzzer, fuzzer->current_vector, fuzzer->current_data, NULL);

                if (should_reconnect) {
                    int delay_ms = bear_options_reconnect_delay_ms(fuzzer->options);
                    g_debug("Reconnecting in %ims...", delay_ms);
                    g_timeout_add(delay_ms, bear_fuzzer_connect, fuzzer);
                } else {
                    g_main_loop_quit(fuzzer->loop);
                }

                return G_SOURCE_REMOVE;
            }

            g_byte_array_append(byte_array, buffer, bytes_available);
        } while (bytes_available == sizeof(buffer) || byte_array->len > 1024 * 1024);

        if (bear_options_verbose(fuzzer->options))
            g_debug("Received %zu bytes @%s", bytes_available, fuzzer->current_vector);

        if (fuzzer->on_receive) {
            g_autoptr(GBytes) data_received = NULL;
            if (byte_array->len > 0)
                data_received = g_bytes_new(byte_array->data, byte_array->len);
            wait_for_data = !fuzzer->on_receive(fuzzer, fuzzer->current_vector, fuzzer->current_data, data_received);
            if (wait_for_data)
                g_message("Waiting for more data @%s (receive callback returned FALSE)", fuzzer->current_vector);
        } else
            wait_for_data = FALSE;
    }

    g_debug("Done receiving data, scheduling next packet");
    schedule_next_packet(fuzzer);
    return G_SOURCE_CONTINUE;
}

static gboolean bear_fuzzer_connect(gpointer user_data) {
    BearFuzzer *fuzzer = BEAR_FUZZER(user_data);

    g_debug("Connecting...");

    const gchar *target = bear_options_get_target(fuzzer->options);
    int port = bear_options_get_port(fuzzer->options);
    if (bear_options_verbose(fuzzer->options))
        g_message("Connecting to %s:%i TCP", target, port);

    g_autoptr(GError) error = NULL;
    fuzzer->client = g_socket_client_new();
    fuzzer->connection = g_socket_client_connect_to_host(fuzzer->client, target, port, NULL, &error);
    if (error) {
        g_warning("Failed to connect to %s:%i TCP: %s", target, port, error->message);
        if (bear_options_reconnect_on_disconnect(fuzzer->options)) {
            int delay_ms = bear_options_reconnect_delay_ms(fuzzer->options);
            g_debug("Reconnecting in %ims...", delay_ms);
            g_timeout_add(delay_ms, bear_fuzzer_connect, fuzzer);
        } else {
            g_main_loop_quit(fuzzer->loop);
        }
        return G_SOURCE_REMOVE;
    }

    GIOStream *stream = G_IO_STREAM(fuzzer->connection);
    fuzzer->output_stream = g_io_stream_get_output_stream(stream);
    fuzzer->input_stream = g_io_stream_get_input_stream(stream);

    if (!g_pollable_input_stream_can_poll(G_POLLABLE_INPUT_STREAM(fuzzer->input_stream))) {
        g_warning("Input stream is not pollable. You will not be able to receive data.");
    } else {
        fuzzer->source = g_pollable_input_stream_create_source(G_POLLABLE_INPUT_STREAM(fuzzer->input_stream), NULL);
        g_source_set_callback(fuzzer->source, G_SOURCE_FUNC(bear_fuzzer_connection_callback), fuzzer, NULL);
        g_source_attach(fuzzer->source, NULL);
    }

    fuzzer->connected = TRUE;
    g_message("Connected to %s:%i TCP", target, port);
    if (fuzzer->on_connect)
        fuzzer->on_connect(fuzzer, fuzzer->current_vector);

    schedule_next_packet(fuzzer);
    return G_SOURCE_REMOVE;
}

gsize bear_fuzzer_send(BearFuzzer *fuzzer, GBytes *bytes) {
    gsize size;
    const guint8 *data = g_bytes_get_data(bytes, &size);
    gsize bytes_written = 0;

    g_autoptr(GError) error = NULL;
    g_output_stream_write_all(fuzzer->output_stream, data, size, &bytes_written, NULL, &error);
    if (error) {
        g_warning("Failed to write to socket: %s", error->message);
        return 0;
    }

    return bytes_written;
}

gsize *bear_fuzzer_get_vector_values(const gchar *vector, gsize *out_num_values) {
    gsize num_values = 0;
    for (gsize i = 0; vector[i]; i++) {
        if (vector[i] == ':')
            num_values++;
    }
    gsize *values = g_new0(gsize, num_values);

    gchar **tokens = g_strsplit(vector, ":", -1);
    for (gsize i = 1; tokens[i]; i++) {
        values[i - 1] = g_ascii_strtoull(tokens[i], NULL, 10);
    }
    if (out_num_values)
        *out_num_values = num_values;
    g_strfreev(tokens);
    return values;
}

static const gchar *get_effective_start_vector(BearFuzzer *fuzzer) {
    const gchar *vector = bear_options_get_start_vector(fuzzer->options);
    if (vector != NULL && bear_generator_validate_vector(fuzzer->generator, vector))
        return vector;
    return bear_generator_get_start_vector(fuzzer->generator);
}

static gboolean send_next_packet(gpointer user_data) {
    BearFuzzer *fuzzer = BEAR_FUZZER(user_data);

    fuzzer->send_next_packet_handle = 0;

    if (!fuzzer->connected) {
        g_debug("Not connected, trying to connect...");
        g_idle_add(bear_fuzzer_connect, fuzzer);
        return G_SOURCE_REMOVE;
    }

    BearGenerator *generator = bear_fuzzer_get_generator(fuzzer);

    g_free(fuzzer->current_vector);
    fuzzer->current_vector = NULL;
    const gchar *vector = bear_generator_get_current_vector(generator);
    if (vector == NULL || fuzzer->num_packets-- <= 0) {
        g_message("Nothing more to send.");
        g_main_loop_quit(fuzzer->loop);
        return G_SOURCE_REMOVE;
    }

    fuzzer->current_vector = g_strdup(vector);

    g_bytes_unref(fuzzer->current_data);
    fuzzer->current_data = bear_generator_get_data(fuzzer->generator, fuzzer->current_vector);
    if (!fuzzer->current_data) {
        g_message("No data for vector %s", fuzzer->current_vector);
        return G_SOURCE_CONTINUE;
    }

    gsize data_size = g_bytes_get_size(fuzzer->current_data);
    g_message("#%zu @%s size: %zu", ++fuzzer->packet_seq, fuzzer->current_vector, data_size);

    gsize sent = bear_fuzzer_send(fuzzer, fuzzer->current_data);
    if (sent != data_size)
        g_message("Send error @%s (sent %zu/%zu bytes)", fuzzer->current_vector, sent, data_size);

    if (fuzzer->receive_timeout_handle)
        g_source_remove(fuzzer->receive_timeout_handle);
    // TODO make this number an option
    fuzzer->receive_timeout_handle = g_timeout_add(2000, receive_timeout_handler, fuzzer);
    bear_generator_increment_vector(fuzzer->generator);

    return G_SOURCE_REMOVE;
}

void bear_fuzzer_run(BearFuzzer *fuzzer) {
    g_return_if_fail(BEAR_IS_FUZZER(fuzzer));
    g_return_if_fail(fuzzer->values != NULL);

    const gchar *target = bear_options_get_target(fuzzer->options);
    int port = bear_options_get_port(fuzzer->options);
    if (!target || port <= 0) {
        g_error("No target or port specified. Use --target and --port options (see "
                "--help).");
        return;
    }
    g_message("Running fuzzer on target: %s:%i", target, port);

    if (bear_fuzzer_get_generator(fuzzer) == NULL) {
        g_error("Failed to create generator");
        return;
    }

    const gchar *given_start_vector = bear_options_get_start_vector(fuzzer->options);
    if (given_start_vector && !bear_generator_validate_vector(fuzzer->generator, given_start_vector)) {
        g_warning("Invalid start vector \"%s\".", given_start_vector);
        return;
    }

    bear_generator_set_vector(fuzzer->generator, get_effective_start_vector(fuzzer));
    g_message("Start vector: %s", bear_generator_get_current_vector(fuzzer->generator));
    g_message("Last vector: %s", bear_generator_get_last_vector(fuzzer->generator));

    fuzzer->num_packets = bear_options_get_num_packets_to_send(fuzzer->options);
    gsize total_variability = bear_generator_total_variability(fuzzer->generator);
    if (fuzzer->num_packets == 0)
        fuzzer->num_packets = total_variability;
    fuzzer->packet_seq = 0;

    fuzzer->loop = g_main_loop_new(NULL, FALSE);
    schedule_next_packet(fuzzer);
    g_unix_signal_add(SIGINT, (GSourceFunc)g_main_loop_quit, fuzzer->loop);
    g_unix_signal_add(SIGTERM, (GSourceFunc)g_main_loop_quit, fuzzer->loop);
    g_main_loop_run(fuzzer->loop);
}

BearGenerator *bear_fuzzer_get_generator(BearFuzzer *fuzzer) {
    g_return_val_if_fail(BEAR_IS_FUZZER(fuzzer), NULL);

    if (!fuzzer->generator) {
        fuzzer->generator = bear_generator_new(fuzzer->values);
    }

    return fuzzer->generator;
}
