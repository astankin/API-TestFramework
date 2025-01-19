import sqlite3

database_path = r"C:\Users\user\Documents\Python\Django-React_Ecommerce\StankinShop\backend\db.sqlite3"
table_name = "auth_user"


def delete_users():
    cursor = None
    connection = None
    try:
        # Connect to the SQLite database
        connection = sqlite3.connect(database_path)
        cursor = connection.cursor()

        # Create a temporary table to store the IDs to keep
        cursor.execute("CREATE TEMP TABLE temp_ids AS SELECT id FROM auth_user ORDER BY id LIMIT 4")

        # Delete rows from the main table that are not in the temp_ids table
        cursor.execute(f"""
            DELETE FROM {table_name}
            WHERE id NOT IN (SELECT id FROM temp_ids)
        """)

        # Commit the changes
        connection.commit()

        print("Users deleted except the first 3 successfully.")
    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
    finally:
        # Close the database connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def fetch_and_print_users():
    cursor = None
    connection = None
    try:
        # Connect to the SQLite database
        connection = sqlite3.connect(database_path)
        cursor = connection.cursor()

        # Define and execute the SELECT query
        fetch_users_query = f"SELECT * FROM {table_name} ORDER BY id"
        cursor.execute(fetch_users_query)

        # Fetch all rows
        users = cursor.fetchall()

        # Print each user
        for user in users:
            print(user)

    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
    finally:
        # Close the database connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def delete_user_by_id(user_id):
    connection = None
    try:
        # Connect to the SQLite database
        connection = sqlite3.connect(database_path)
        cursor = connection.cursor()

        # Execute the delete query
        cursor.execute(f"DELETE FROM {table_name} WHERE id = ?", (user_id,))

        # Commit the changes
        connection.commit()
        if cursor.rowcount > 0:
            print(f"User with ID {user_id} deleted successfully.")
        else:
            print(f"No user found with ID {user_id}.")
    except sqlite3.Error as e:
        print(f"Database error occurred: {e}")
    finally:
        # Ensure resources are cleaned up
        if connection:
            connection.close()


if __name__ == "__main__":
    delete_users()
    #fetch_and_print_users()
