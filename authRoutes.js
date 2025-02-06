require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  InitiateAuthCommand,
  AdminSetUserPasswordCommand,
  AdminGetUserCommand,
} = require("@aws-sdk/client-cognito-identity-provider");

const router = express.Router();

// Initialize AWS CognitoIdentityProviderClient
const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.COGNITO_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID, // Access key
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, // Secret key
  },
});

// Helper function to calculate SECRET_HASH
function calculateSecretHash(username) {
  return crypto
    .createHmac("SHA256", `${process.env.COGNITO_APP_CLIENT_SECRET}`)
    .update(username + `${process.env.COGNITO_APP_CLIENT_ID}`)
    .digest("base64");
}

const checkIfUsernameExists = async (username) => {
  const params = {
    UserPoolId: process.env.COGNITO_USER_POOL_ID,
    Username: username,
  };

  try {
    const command = new AdminGetUserCommand(params);
    const data = await cognitoClient.send(command);
    console.log("Username Exists");
    // const result = await cognitoIdentityServiceProvider.adminGetUser(params).promise();
    return true; // User already exists
  } catch (err) {
    if (err.code === "UserNotFoundException") {
      return false; // Username is available
    }
    console.log("Username available");
    // console.error("Error checking username existence:", err);
    // throw err;
  }
};

/**
 * @route POST /auth/signup
 * @desc Registers a new user with email and password
 * @body { email: string, password: string }
 */
router.post("/signup", async (req, res) => {
  const { email, password, tenantId, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  const clientAppId = process.env.COGNITO_APP_CLIENT_ID;
  console.log("Client", clientAppId);
  const params = {
    UserPoolId: process.env.COGNITO_USER_POOL_ID,
    ClientId: process.env.COGNITO_APP_CLIENT_ID,
    Username: `${email}-${tenantId}-${role}`,
    Password: password,
    UserAttributes: [
      {
        Name: "email",
        Value: email,
      },
      { Name: "email_verified", Value: "true" },
      { Name: "custom:tenantId", Value: tenantId },
      { Name: "custom:role", Value: role },
    ],
    SecretHash: calculateSecretHash(email),
  };

  try {
    const userExists = await checkIfUsernameExists(
      `${email}-${tenantId}-${role}`
    );
    if (!userExists) {
      const command = new AdminCreateUserCommand(params);
      const data = await cognitoClient.send(command);

      // Step 2: Set a permanent password and mark the user as confirmed
      const setPasswordParams = {
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: `${email}-${tenantId}-${role}`,
        Password: password,
        Permanent: true,
      };
      const commandConfirmPassword = new AdminSetUserPasswordCommand(
        setPasswordParams
      );
      await cognitoClient.send(commandConfirmPassword);

      res.status(200).json({
        message: "User signed up successfully",
        userSub: data.UserSub,
      });
    } else {
      console.log("User already exists");
      res.status(400).json({ error: "User already exists" });
    }
  } catch (err) {
    res.status(400).json({ error: err?.message || "Signup failed" });
  }
});

/**
 * @route POST /auth/login
 * @desc Authenticates a user and returns tokens
 * @body { email: string, password: string }
 */
router.post("/login", async (req, res) => {
  const { email, password, tenantId, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const params = {
    AuthFlow: "USER_PASSWORD_AUTH",
    ClientId: process.env.COGNITO_APP_CLIENT_ID,
    AuthParameters: {
      USERNAME: `${email}-${tenantId}-${role}`,
      PASSWORD: password,
      SECRET_HASH: calculateSecretHash(`${email}-${tenantId}-${role}`),
    },
  };

  try {
    const command = new InitiateAuthCommand(params);
    const data = await cognitoClient.send(command);

    res.status(200).json({
      message: "Login successful",
      accessToken: data.AuthenticationResult.AccessToken,
      idToken: data.AuthenticationResult.IdToken,
      refreshToken: data.AuthenticationResult.RefreshToken,
    });
  } catch (err) {
    res.status(400).json({ error: err.message || "Login failed" });
  }
});

module.exports = router;
