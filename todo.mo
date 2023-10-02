import Text;
import Bcrypt;
import Sql;
import SQL.Connection;
import SQL.Driver;

// Define a User record to represent the user table in the database
public type User = {
  id: Nat;
  phone: Text;
  firstname: Text;
  lastname: Text;
  passwordHash: Text; // Store the hashed password
};

// Define a Task record to represent the task table in the database
public type Task = {
  id: Nat;
  userId: Nat;
  text: Text;
};

// Function to hash a password using a secure hashing algorithm (bcrypt)
public func hashPassword(password: Text) : Text {
  return Bcrypt.hash(password);
};

// Function to verify a password by comparing it to a hashed password
public func verifyPassword(password: Text, hashedPassword: Text) : Bool {
  return Bcrypt.verify(password, hashedPassword);
};

// Function to establish a MySQL database connection
public func connectToMySQLDatabase() : SQL.Connection {
  // Configure the MySQL database connection parameters
  let connectionSettings = SQL.ConnectionSettings(
    driver = SQL.Driver.MySQL,
    host = "localhost",
    port = 3306, // Default MySQL port
    username = "root",
    password = " ",
    database = "ratiba" // The name of your MySQL database
  );

  // Establish the database connection
  return SQL.connect(connectionSettings);
}

// Function to handle user registration
public shared func signup(phone: Text, firstname: Text, lastname: Text, password: Text) : async Bool {
  let passwordHash = hashPassword(password);
  let mysqlConnection = connectToMySQLDatabase();

  // Insert the new user record into the MySQL database using the MySQL connection
  let insertResult = await SQL.execute({
    connection = mysqlConnection,
    statement = "INSERT INTO users (phone, firstname, lastname, passwordHash) VALUES (?, ?, ?, ?)",
    arguments = [phone, firstname, lastname, passwordHash]
  });

  if (insertResult.error) {
    // Handle the case where the insertion fails
    SQL.close(mysqlConnection);
    return false;
  }

  // Close the MySQL connection when done
  SQL.close(mysqlConnection);

  return true; // Return true on successful signup
}

// Function to handle user login
public shared func login(phone: Text, password: Text) : async Bool {
  let mysqlConnection = connectToMySQLDatabase();

  // Retrieve the user record from the database based on the phone number
  let userQuery = await SQL.query<User>({
    connection = mysqlConnection,
    statement = "SELECT * FROM users WHERE phone = ?",
    arguments = [phone]
  });

  // Close the MySQL connection when done
  SQL.close(mysqlConnection);

  // Check if a user with the provided phone number exists
  if (Array.isEmpty(userQuery)) {
    return false; // User does not exist
  }

  let user = userQuery[0];

  // Verify the provided password by comparing it to the hashed password in the database
  if (verifyPassword(password, user.passwordHash)) {
    return true; // Successful login
  }

  return false; // Password incorrect
}

// Function to add a task for a user
public shared func addTask(userId: Nat, text: Text) : async Bool {
  let mysqlConnection = connectToMySQLDatabase();

  // Insert the new task record into the MySQL database using the MySQL connection
  let insertResult = await SQL.execute({
    connection = mysqlConnection,
    statement = "INSERT INTO tasks (userId, text) VALUES (?, ?)",
    arguments = [userId, text]
  });

  // Close the MySQL connection when done
  SQL.close(mysqlConnection);

  if (insertResult.error) {
    // Handle the case where task insertion fails
    return false;
  }

  return true;
}

// Function to get tasks for a user
public shared func getTasks(userId: Nat) : async [Task] {
  let mysqlConnection = connectToMySQLDatabase();

  // Retrieve tasks for the given user from the database
  let tasksQuery = await SQL.query<Task>({
    connection = mysqlConnection,
    statement = "SELECT * FROM tasks WHERE userId = ?",
    arguments = [userId]
  });

  // Close the MySQL connection when done
  SQL.close(mysqlConnection);

  return tasksQuery;
}
