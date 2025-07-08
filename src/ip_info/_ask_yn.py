
def _ask_yn(
    question: str,
    *,
    true: str = "y"
) -> bool:
    """
    Prompt the user with a yes/no question.

    Args:
        question: Text of the prompt.
        true: Which response ("y" or "n") should be treated as True.
              Defaults to "y".

    Returns:
        bool: True  if the user's choice matches `true`
              False otherwise.
    """
    true = true.lower()
    if true not in ("y", "n"):
        raise ValueError("true must be 'y' or 'n'")

    while True:
        choice = input(f"{question} (y/n): ").strip().lower()
        if choice in ("y", "n"):
            return choice == true
        print("Please enter 'y' or 'n'.")
