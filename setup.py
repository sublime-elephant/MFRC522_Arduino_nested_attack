from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "hot",
        sources=["hot.cpp", 
                 "C:\\Users\\username\\Documents\\PlatformIO\\Projects\\MIFARECRACK\\lib\\MFRC522\\crypto1.c",
                 "C:\\Users\\username\\Documents\\PlatformIO\\Projects\\MIFARECRACK\\lib\\MFRC522\\crapto1.c"
        ],
        include_dirs=[pybind11.get_include(), "C:\\Users\\username\\Documents\\PlatformIO\\Projects\\MIFARECRACK\\lib\\MFRC522"],
        language="c++",
    ),
]

setup(
    name="hot",
    version="0.1",
    ext_modules=ext_modules,
)