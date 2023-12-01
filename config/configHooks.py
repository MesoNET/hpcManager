"""
    Hook to handle filters's static value for an attribute into a dynamic 
    computed value.

    A hook can for example convert a configured value into a static value 
    usable in command line as '--filter "gramc_asession=[NEW]"'

    These is no session in GRAMC meso.
"""
# Import global configuration
import config.configGramc as grconfig
hooks = {  
    "gramc": {
        "asession": {
            "[NEW]": lambda o: f"^{grconfig['session']['new']}$",
            "[CURRENT]": lambda o: f"^{'|'.join(grconfig['session']['current'])}$",
            # https://stackoverflow.com/questions/55918348/regex-does-not-contain-multiple-words
            "[OLD]": lambda o: "^((?!(" + f"{'|'.join([grconfig['session']['new']]+grconfig['session']['current'])}" + ")).)*$"
        },
        "lsession": {
            "[NEW]": lambda o: f"^{grconfig['session']['new']}$",
            "[CURRENT]": lambda o: f"^{'|'.join(grconfig['session']['current'])}$",
            "[OLD]": lambda o: "^((?!(" + f"{'|'.join([grconfig['session']['new']]+grconfig['session']['current'])}" + ")).)*$"
        },
        "apsession": {
            "[NEW]": lambda o: f"^{grconfig['session']['new']}$",
            "[CURRENT]": lambda o: f"^{'|'.join(grconfig['session']['current'])}$",
            "[OLD]": lambda o: "^((?!(" + f"{'|'.join([grconfig['session']['new']]+grconfig['session']['current'])}" + ")).)*$"
        },
        "lpsession": {
            "[NEW]": lambda o: f"^{grconfig['session']['new']}$",
            "[CURRENT]": lambda o: f"^{'|'.join(grconfig['session']['current'])}$",
            "[OLD]": lambda o: "^((?!(" + f"{'|'.join([grconfig['session']['new']]+grconfig['session']['current'])}" + ")).)*$"
        },
    }
}