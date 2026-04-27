from streamlit.testing.v1 import AppTest

def test_home_page():
    at = AppTest.from_file("frontend.py")
    at.run(timeout=10)
    
    assert at.title[0].value == "Windows-Based Password Recovery 🔐"
    assert at.sidebar.text_input[0].value == "CASE-0012025"

def test_navigation_and_attack_configuration():
    at = AppTest.from_file("frontend.py")
    at.run()

    at.sidebar.radio[0].set_value("Attack Page").run()
    assert at.title[0].value == "Select recovery method ⚙️"

    at.radio[0].set_value("Dictionary-based").run()

    for button in at.button:
        if button.label == "Save attack configuration":
            button.click().run()
            break
    
    assert at.session_state['attack_config'] == "Dictionary-based"
    assert at.success[0].value == "Configuration saved: Dictionary-based"