test_deps = [ glib_dep, libbear_dep ]

test('fuzzer-data',
    executable('test-fuzzer-data',
        'test-fuzzer-data.c',
        dependencies : test_deps,
        install : false)
)

test('vectors',
    executable('test-vectors',
        'test-vectors.c',
        dependencies : test_deps,
        install : false)
)

test('fuzzy-value',
    executable('test-fuzzy-value',
        'test-fuzzy-value.c',
        dependencies : test_deps,
        install : false)
)

test('blocks',
    executable('test-blocks',
        'test-blocks.c',
        dependencies : test_deps,
        install : false)
)

test('tools',
    executable('test-tools',
        'test-tools.c',
        dependencies : test_deps,
        install : false)
)
