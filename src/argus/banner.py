"""ASCII banner for ARGUS - Automated Response & Guided Unified Security."""

BANNER = r"""
                              .  *  .  *  .  *  .
                           *    (@)  (@)  (@)    *
                         .   (@)  (@)  (@)  (@)   .
                        *  (@) (@) (@) (@) (@) (@)  *
                       . (@)(@)(@)(@)(@)(@)(@)(@)(@) .
                       *(@)(@)(@)(@)(@)(@)(@)(@)(@)(@)*
                        '(@)(@)(@)(@)(@)(@)(@)(@)(@)'
                          '(@)(@)(@)(@)(@)(@)(@)'
                            '  ' '  ' '  ' '  '
                                  \   |   /
                                   \  |  /
                                    \_|_/
                                   /     \        ___    ____   _____ _    _  _____
                                  |  o o  |      / _ \  |  _ \ / ____| |  | |/ ____|
                                  |   <   |     | |_| | | |_) | |  __| |  | | (___
                                   \ --- /      |  _  | |  _ <| | |_ | |  | |\___ \
                                    |   |       | | | | | |_) | |__| | |__| |____) |
                                   /|   |\      |_| |_| |____/ \_____|\____/|_____/
                                  / |   | \
                                 /  |   |  \    Automated Response &
                                '   '   '   '   Guided Unified Security

                                                v0.1.0
"""

BANNER_SMALL = r"""
        (@) (@) (@)
       (@)(@)(@)(@)(@)
         \    |    /
          \   |   /
           \_/ \_/
            (o o)      _    ____   ____ _   _ ____
             \ /      / \  |  _ \ / ___| | | / ___|
             -+-     / _ \ | |_) | |  _| | | \___ \
            / | \   / ___ \|  _ <| |_| | |_| |___) |
                   /_/   \_\_| \_\\____|\___/|____/

 Automated Response & Guided Unified Security
"""


def print_banner(small: bool = False) -> None:
    """Print the ARGUS ASCII banner."""
    from rich.console import Console
    from rich.text import Text

    console = Console()
    banner = BANNER_SMALL if small else BANNER
    text = Text(banner)
    text.stylize("cyan")
    console.print(text)
