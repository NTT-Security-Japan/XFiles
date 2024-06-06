from setuptools import setup

setup(  
        name="xfiles",
        version="0.1.0",
        install_requires=["cryptography","chardet","lxml"],
        packages=setuptools.find_packages(where='src'),
        py_modules=["command"],
        entry_points={
            "console_scripts":[
                "xfiles = command:main"
            ]
        },
        package_dir = {'': 'src'},
        classifiers=[
            'Natural Language :: English',
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
)