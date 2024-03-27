const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcrypt');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const cors = require('cors');
const app = express();
const session = require('express-session'); // Import express-session
// Enable CORS for all routes with specific origin
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true, // Allow credentials (cookies)
}));
// Set up session middleware
app.use(session({
  secret: 'your_secret_key', // Change this to a random secret key
  resave: false,
  saveUninitialized: false,
}));

async function encryptData(plaintextData) {
  // Create a KMS client
  const kmsClient = new KeyManagementServiceClient({
    keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    projectId: process.env.PROJECT_ID,
  });

  // Set the key resource name
  const keyName = process.env.KEY_RESOURCE;

  // Convert the plaintext data to a Buffer
  const plaintextBuffer = Buffer.from(plaintextData);

  try {
    // Encrypt the plaintext data using the specified key
    const [result] = await kmsClient.encrypt({
      name: keyName,
      plaintext: plaintextBuffer,
    });

    // The result contains the encrypted ciphertext
    return result.ciphertext.toString('base64');
  } catch (error) {
    console.error('Error encrypting data:', error);
    throw error;
  }
}

async function decryptData(encryptedData) {
  // Create a KMS client
  const kmsClient = new KeyManagementServiceClient({
    keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    projectId: process.env.PROJECT_ID,
  });

  // Set the key resource name
  const keyName = process.env.KEY_RESOURCE;

  // Convert the base64-encoded ciphertext to a Buffer
  const ciphertextBuffer = Buffer.from(encryptedData, 'base64');

  try {
    // Decrypt the ciphertext data using the specified key
    const [result] = await kmsClient.decrypt({
      name: keyName,
      ciphertext: ciphertextBuffer,
    });

    // The result contains the decrypted plaintext
    return result.plaintext.toString();
  } catch (error) {
    console.error('Error decrypting data:', error);
    throw error;
  }
}

// Enable CORS for all routes
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.get('/profile', (req, res) => {
  const currentUser = req.session.user; // Access currently logged-in user
  console.log(currentUser)
  console.log("current user is above")
  // Check if user is logged in
  if (!currentUser) {
    // Redirect to login page or send unauthorized response
    return res.status(401).send('Unauthorized');
  }
  
  // Send the username as the response
  res.send(currentUser.username);
});

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true, 
    deprecationErrors: true,
  },
});

// Connect to MongoDB when the application starts
async function connectToMongo() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
}

// Disconnect from MongoDB when the application is closing
async function disconnectFromMongo() {
  try {
    await client.close();
    console.log("Disconnected from MongoDB!");
  } catch (error) {
    console.error('Error disconnecting from MongoDB:', error);
  }
}

// Set up the 'beforeExit' event listener
process.on('beforeExit', () => {
  disconnectFromMongo();
});

/***************************** Authentication methods *****************************/

app.post('/api/auth', async (req, res) => {
  const { username, password } = req.body;
  console.log({username});
  console.log({password});

  try {
    const user = await client.db("computersecurity").collection("user").findOne({ username });

    if (!user) {
      return res.status(401).json({ message: 'Username does not exist' });
    }

    const decryptedPassword = await decryptData(user.password);

    if (decryptedPassword != password) {
      return res.status(401).json({ message: 'Invalid password' });
    }
    // Store user information in session
    req.session.user = user;
    console.log("REYHAN HERE IS THE USER");
    console.log(req.session.user);
    req.session.save()
    // You can customize the response or generate a token for authentication
    res.status(200).json({ message: 'Authentication successful' });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Endpoint for user registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the username already exists
    const existingUser = await client.db("computersecurity").collection("user").findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Encrypt the password before saving it
    const encryptedPassword = await encryptData(password);

    // Create a new user document
    const newUser = {
      username,
      password: encryptedPassword,
    };

    // Insert the new user document into the database
    await client.db("computersecurity").collection("user").insertOne(newUser);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


// Start the server
connectToMongo().then(() => {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});
