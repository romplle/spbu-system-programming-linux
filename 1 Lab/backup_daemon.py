import os
import time
import shutil
import logging
import configparser
from datetime import datetime
import signal
import sys


def load_settings(file_path):
    parser = configparser.ConfigParser()
    parser.read(file_path)

    settings = {
        'source_path': parser.get('Settings', 'source_dir'),
        'destination_path': parser.get('Settings', 'backup_dir'),
        'interval': parser.getint('Settings', 'backup_interval'),
        'log_path': parser.get('Settings', 'log_file')
    }
    return settings


def setup_logger(log_path):
    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(message)s')


def perform_backup(source, destination):
    if not os.path.exists(destination):
        os.makedirs(destination)

    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    backup_location = os.path.join(destination, f"backup_{timestamp}")
    shutil.copytree(source, backup_location)
    logging.info(f"Backup created: {backup_location}")


def signal_handler(signum, frame):
    logging.info("Backup service is stopping.")
    sys.exit(0)


def backup_service(config_file):
    config = load_settings(config_file)
    setup_logger(config['log_path'])
    logging.info("Backup service started.")

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    while True:
        perform_backup(config['source_path'], config['destination_path'])
        time.sleep(config['interval'])


if __name__ == "__main__":
    configuration_file = '/home/romplle/system-programming-linux/1 Lab/backup_config.ini'
    backup_service(configuration_file)
