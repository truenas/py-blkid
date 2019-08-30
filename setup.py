import sys
from collections import namedtuple
from setuptools import setup

try:
    from Cython.Distutils import build_ext
    from Cython.Distutils.extension import Extension
except ImportError:
    raise ImportError("This package requires Cython to build properly. Please install it first.")

try:
    import config
except ImportError:
    if 'build' in sys.argv or 'install' in sys.argv:
        raise ImportError('Please execute configure script first')
    else:
        config = namedtuple('config', ['CFLAGS', 'LDFLAGS'])([], [])

setup(
    name='blkid',
    version='0.1',
    setup_requires=[
        'setuptools>=18.0',
        'Cython',
    ],
    cmdclass={'build_ext': build_ext},
    ext_modules=[
        Extension(
            'blkid',
            ['libblkid.pyx'],
            extra_compile_args=config.CFLAGS,
            extra_link_args=config.LDFLAGS,
        )
    ]
)
