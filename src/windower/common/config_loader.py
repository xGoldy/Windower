"""
Configuration loading and management from YAML configuration files.

Author: Patrik Goldschmidt (igoldschmidt@fit.vut.cz)
Author: Jan Kučera (jan.kucera@cesnet.cz)
Date: 2023-05-17
Project: Windower: Feature Extraction for Real-Time DDoS Detection Using ML
Repository: https://github.com/xGoldy/Windower
"""

import yaml

from common import defines


class ConfigParamsError(Exception):
    """Configuration parameters exception such as missing mandatory parameter or invalid parameter value."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg)


def load_config(cfg_file: str) -> dict:
    """Loads configuration file and returns a corresponding dictionary.

    Parameters:
        cfg_file Path to file containing configuration

    Raises:
        FileNotFoundError if the supplied file does not exist

    Returns:
        dict Dictionary corresponding to the loaded configuration"""

    # Load configuration file
    config = None

    with open(cfg_file, 'r') as stream_config:
        config = yaml.safe_load(stream_config)

    return config


def load_prog_config(cfg_file: str, params_setup: dict) -> dict:
    """Loads program configuration from YAML file specified by cfg_file, fills default parameters, perform checks for
    mandatory parameters and their expected types.

    Parameters:
        cfg_file Path to YAML configuration file to load
        params   Dictionary of params which to process in YAML config based on common.defines CONF_PARAMS* naming

    Returns:
        dict Dictionary with loaded configuration from the given file"""

    config = None

    # Extract parameters setup
    mandatory_params = params_setup[defines.CONF_PARAMS_MANDATORY]
    default_values   = params_setup[defines.CONF_PARAMS_DEFAULTS]
    int_params       = params_setup[defines.CONF_PARAMS_INTS]
    float_params     = params_setup[defines.CONF_PARAMS_FLOATS]
    string_params    = params_setup[defines.CONF_PARAMS_STRINGS]
    bool_params      = params_setup[defines.CONF_PARAMS_BOOLS]

    # Load configuration file
    with open(cfg_file, 'r') as stream_config:
        config = yaml.safe_load(stream_config)

    try:
        # Check for mandatory configuration parameters
        for mandatory_key in mandatory_params.keys():
            for mandatory_param in mandatory_params[mandatory_key]:
                if mandatory_param not in config[mandatory_key]:
                    raise ConfigParamsError("Mandatory parameter \"{}\" missing for {}".format(mandatory_param,
                        mandatory_key))
    except KeyError as key_err:
        raise ConfigParamsError("Required config key {} not present in {}".format(key_err, cfg_file))

    # Fill-in omitted parameters
    for default_param_key in default_values.keys():
        for default_param, default_value in default_values[default_param_key].items():
            if default_param not in config[default_param_key]:
                config[default_param_key][default_param] = default_value

    # Check if specified parameters match their desired types
    for param_key in int_params:
        for param in int_params[param_key]:
            if param in config[param_key]:
                # Integer parameters check only against integers
                if not isinstance(config[param_key][param], int):
                    raise ConfigParamsError("Parameter \"{}\" for {} must be an integer".format(param, param_key))

    for param_key in float_params:
        for param in float_params[param_key]:
            if param in config[param_key]:
                # Float parameters check against floats and integers
                if not isinstance(config[param_key][param], (float, int)):
                    raise ConfigParamsError("Parameter \"{}\" for {} must be a numeric value".format(param, param_key))

    for param_key in string_params:
        for param in string_params[param_key]:
            if param in config[param_key]:
                # String parameters check against list of acceptable strings
                if config[param_key][param] not in string_params[param_key][param]:
                    raise ConfigParamsError("Configuration value of \"{}\" for {} is invalid".format(
                        config[param_key][param], param))

    for param_key in bool_params:
        for param in bool_params[param_key]:
            if param in config[param_key]:
                if not isinstance(config[param_key][param], bool):
                    raise ConfigParamsError("Parameter \"{}\" for {} must be a bool".format(param, param_key))

    return config


def install_config(script_name: str, script_config: dict | None, modules) -> dict:
    """Installs provided modules config to the overall script configuration.

    Parameters:
        script_name   Name of the calling script
        script_config Script existing configuration
        modules       Single or list of module objects to import

    Returns:
        dict Modified configuration dictionary with the module's configuration installed."""

    # Create configuration-form template
    config = {
        defines.CONF_PARAMS_MANDATORY: {},
        defines.CONF_PARAMS_DEFAULTS: {},
        defines.CONF_PARAMS_INTS: {},
        defines.CONF_PARAMS_FLOATS: {},
        defines.CONF_PARAMS_STRINGS: {},
        defines.CONF_PARAMS_BOOLS: {}
    }

    if not isinstance(modules, list):
        modules = [modules]

    # Initialize with initial script configuration
    if script_config is not None:
        for key, val in script_config.items():
            if val is not None:
                config[key][script_name] = val

    # Initialize with imported modules configuration
    for module in modules:
        mod_name = module.MODULE_NAME

        for key, val in module.MODULE_CONFIG.items():
            if val is not None:
                config[key][mod_name] = val

    return config
