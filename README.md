# Project Setup Instructions

To test the functionality of the login and register features, you'll need to set up a database. We'll use SQLite for simplicity. Follow the steps below to get everything started:

## Getting Started

### Prerequisites

Ensure you have Python 3 installed on your system. You can check your Python version by running:

```sh
python3 --version
```

### Setting Up the Database

1. Open a terminal and start the Python interpreter:

    ```sh
    python3
    ```

2. Import the necessary modules from your application:

    ```python
    from app import app, db
    ```

3. Create an application context to work with the database:

    ```python
    app.app_context().push()
    ```

4. Create all the necessary database tables:

    ```python
    db.create_all()
    ```

5. Exit the Python interpreter by pressing `Ctrl+D` or typing `exit()`.

### Running the Flask Application

After setting up the database, you can run your Flask application to test the login and register features.

1. In your terminal, navigate to the directory where your Flask application is located.

2. Run the Flask application:

    ```sh
    flask run
    ```

3. Open your web browser and navigate to `http://127.0.0.1:5000` to access your application.

### Testing the Features

Now that your application is running, you can test the login and register features:

1. **Register a New User:**
   - Navigate to the registration page.
   - Fill in the necessary details and submit the form.

2. **Login with an Existing User:**
   - Navigate to the login page.
   - Enter the credentials of a registered user and submit the form.

### Additional Notes

- Make sure your `app` module is correctly configured with the necessary configurations for the database.
- If you encounter any issues, check your Flask application logs for detailed error messages.

### Troubleshooting

If you encounter any issues, consider the following:

- Ensure all dependencies are installed. You can use a virtual environment to manage your project dependencies:

    ```sh
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

- Check for typos in your code, especially in the import statements and method calls.
- Refer to the Flask documentation for more detailed explanations on context management and database setup.

## Conclusion

By following these steps, you should be able to set up the SQLite database, run your Flask application, and test the login and register features successfully.

