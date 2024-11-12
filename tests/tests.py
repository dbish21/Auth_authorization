from unittest import TestCase
from app import app
from models import db, User, Feedback

# Use test database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///feedback_test'
app.config['SQLALCHEMY_ECHO'] = False
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False

class UserTestCase(TestCase):
    """Tests for views about users."""

    def setUp(self):
        """Add sample user."""
        db.drop_all()
        db.create_all()

        self.client = app.test_client()

        # Create test user
        self.user = User.register(
            username="testuser",
            password="testpass",
            email="test@test.com",
            first_name="Test",
            last_name="User"
        )
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        """Clean up any fouled transaction."""
        db.session.rollback()

    def test_home_page(self):
        """Make sure home page loads."""
        with self.client as client:
            resp = client.get("/")
            html = resp.get_data(as_text=True)

            self.assertEqual(resp.status_code, 302)

    def test_register_form(self):
        """Test if register form displays."""
        with self.client as client:
            resp = client.get("/register")
            html = resp.get_data(as_text=True)

            self.assertEqual(resp.status_code, 200)
            self.assertIn('Register', html)

    def test_login_form(self):
        """Test if login form displays."""
        with self.client as client:
            resp = client.get("/login")
            html = resp.get_data(as_text=True)

            self.assertEqual(resp.status_code, 200)
            self.assertIn('Login', html)

if __name__ == '__main__':
    import unittest
    unittest.main()