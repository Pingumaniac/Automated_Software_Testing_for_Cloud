#!/bin/bash
python3 test.py
python3 database_setup.py
python3 test_unit.py
python3 plot_metrics_unit.py
python3 test_atheris.py
python3 plot_metrics_atheris.py
