import unittest
# from my_python_project.main import *
import sys
sys.path.append("../src")
from main import app

class TestMain(unittest.TestCase):

    class TestMain(unittest.TestCase):

        def setUp(self):
            self.app = app.test_client()
            self.app.testing = True

        def test_hello_world(self):
            response = self.app.get('/')
            response = self.app.get('/', headers={"Authorization": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJlYzVkMTBlZi04N2MwLTQxYTItYTIyZC1hOGE1NGQ1Y2Q2NzciLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vMzEyZThmYTUtNjY4YS00MTg4LTkxYmYtODZiODhkMGMzOTJhL3YyLjAiLCJpYXQiOjE3MTU3NjQ2MjAsIm5iZiI6MTcxNTc2NDYyMCwiZXhwIjoxNzE1NzY5MzY2LCJhaW8iOiJBVVFBdS84V0FBQUFaOHh4OXl5THNTcGJiN2JZN3BldnVvMm40NDRrN3ZvdENFQ0tLdS9vOStnMUViRnF4YWkyekh5SnhYKzBraFNmUUFOb1laQjFMMDI4Q0RDR2NOY2daQT09IiwiYXpwIjoiNGZkOGU1MmQtMmVhYi00MDNkLWJkZWYtMmNkNjlhOWZkOTU3IiwiYXpwYWNyIjoiMSIsImdyb3VwcyI6WyIwNzVjZjEwMi03NjMwLTQyNDMtOGI5Yi0yZWQ0MDg0MWY3YWYiLCJkN2JlYTE5MC0yZjM3LTQ5MTQtYTQzMi02NDNmODg3MzUwMzMiLCJiZDhkNDJiYS1hNmFkLTRmMmMtODA1OS05ZjE5MjJjYmQ0NzQiXSwibmFtZSI6IlVzZXIgT25lIiwib2lkIjoiZDNhYjI2NWUtZjI4MS00NGUxLWI3MmEtMzYxYjI0ZTVjYjdmIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiVXNlck9uZUBnb2h2aW4ub3JnIiwicmgiOiIwLkFhOEFwWTh1TVlwbWlFR1J2NGE0alF3NUt1OFFYZXpBaDZKQm9pMm9wVTFjMW5ldkFDdy4iLCJyb2xlcyI6WyJEYXRhLlJlYWRlciJdLCJzY3AiOiJVc2VyX0ltcGVyc29uYXRpb24iLCJzdWIiOiIwRGVqemJ4R1h6QzhqUGU3WUYxVmprbVYzTTVnQmNpQnZhOVF1amFITW1JIiwidGlkIjoiMzEyZThmYTUtNjY4YS00MTg4LTkxYmYtODZiODhkMGMzOTJhIiwidXRpIjoiZURWeGlvZHpvMGlYUFdJbkxZM2pBQSIsInZlciI6IjIuMCJ9.KXueYD4_Xdb0AeOfj4uzCbnXJ6yaNRjTiJ6MAYdF33NR3oGF4YqiAFlw5oXbar-_OACi815M5mG2q3y1v8A64YhkA9BF1BKRhjkAaeQAr6KrlePEqkxfQyR0xaBpHKIiiz-ecG5Tkg8ICvIqlJprhH-sfUrEty1x9DX7Je9TgIx2c9V-N-Tb4HTX800PriGH9FgF4WkdtisH17pI-LQpobMr-tQWuWL-udqhw3Z-w7rrmZzlwsDzHdzMQ2LPRlaDlwg_sM0zDayWyvzmSqD8rhYK-JVyw74ErJ_ffPMBJHe0ccJrDKsxMk73zNAWeIf8c-VDPb5rP_muUfcriJ-G8Q"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode('utf-8'), 'Hello, World!')

if __name__ == '__main__':
        unittest.main()