test_deps = [ glib_dep, libbear_dep ]

test('fuzzer-data',
    executable('fuzzer-data',
        'test-fuzzer-data.c',
        dependencies : test_deps,
        install : false)
)

test('fuzzer-vectors',
    executable('fuzzer-vectors',
        'test-fuzzer-vectors.c',
        dependencies : test_deps,
        install : false)
)

test('fuzzy-value',
    executable('fuzzy-value',
        'test-fuzzy-value.c',
        dependencies : test_deps,
        install : false)
)

test('blocks',
    executable('blocks',
        'test-blocks.c',
        dependencies : test_deps,
        install : false)
)

test('tools',
    executable('tools',
        'test-tools.c',
        dependencies : test_deps,
        install : false)
)
