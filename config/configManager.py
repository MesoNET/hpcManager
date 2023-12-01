# -*- coding: utf-8 -*-
""" Common command lines attribute definition
Should not be modified.
"""
import argparse

continue_on_failure_parser = argparse.ArgumentParser(
    add_help=False
)
continue_on_failure_parser.add_argument(
    "--continue-on-failure", 
    dest=f"common_continue_on_failure", 
    action='store_true',
    required=False,
    help=f"Continue action or command even if an error occurs."
)