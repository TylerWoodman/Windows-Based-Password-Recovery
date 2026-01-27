import datetime
word = "hello"

def rule_append_year(word):
    # Generates versions with years 2015-2026 appended
    variations = []
    current_year = datetime.datetime.now().year
    # Look back 10 years and forward 1 year
    for y in range(current_year - 10, current_year + 2):
        variations.append(f"{word}{y}")
        print(variations)
    return variations

rule_append_year(word)
