try:
    from setuptools import setup
    print("Successfully imported setup from setuptools")
except ImportError as e:
    print(f"ImportError: {e}")
except Exception as e:
    print(f"Error: {e}")
