from setuptools import setup

setup(
    name='hawkular-alerts-module',
    version='0.1.0',
    description='Hawkular Alerts module',
    author='Daniel Korn',
    author_email='dkorn@redhat.com',
    url='https://github.com/dkorn/hawkular-alerts-module',
    package_dir={'': 'library'},
    py_modules=["hawkular_alerts_group_dampening", "hawkular_alerts_group_member",
                "hawkular_alerts_group_trigger"],
    install_requires='ansible hawkular-client-python'.split(),
)
