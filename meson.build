project('bear', 'c',
    version : '0.0.0',
    meson_version: '>= 0.60.0',
    default_options: [
        'prefix=/usr',
        'localstatedir=/var',
    ]
)

glib_dep = [
    dependency('glib-2.0'),
    dependency('gobject-2.0'),
    dependency('gio-2.0'),
    dependency('gio-unix-2.0'),
]

add_project_arguments(
    '-D_GNU_SOURCE',
    '-DG_LOG_USE_STRUCTURED',
    language: 'c'
)

subdir('lib')
subdir('audit')
