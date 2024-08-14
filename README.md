# URL Shortener

## Project Overview
The URL Shortener is a custom URL shortening service built using Node.js and Express.js. It allows users to create short, memorable URLs for long and complex web addresses. The project uses MongoDB as the database to store the shortened URLs and their associated information. The application also implements rate limiting to protect against abuse.

## Key Features
1. **URL Shortening**: Users can submit a long URL, and the application will generate a shortened version of the URL.
2. **Customization**: Users can provide an optional creator name and expiration date for their shortened URLs.
3. **Analytics**: The application tracks various analytics data for each shortened URL, such as the number of clicks, last click timestamp, referrer, IP address, and user agent.
4. **Rate Limiting**: The application limits each IP to 100 requests per 15 minutes to prevent abuse and potential DDoS attacks.

## Project Structure
The project follows a typical Node.js and Express.js structure, with the following key directories and files:

- **`index.js`**: The main entry point for the application. It sets up the Express.js server, connects to the MongoDB database, and defines the routes for URL shortening, redirection, and analytics.
- **`models/urlModel.js`**: This file defines the data model for the shortened URLs, including fields such as `shortId`, `originalUrl`, `creator`, `expirationDate`, `clicks`, `lastClickAt`, and `analytics`.
- **`public/index.html`**: This file contains the HTML template for the user interface, allowing users to submit URLs for shortening.
- **`public/script.js`**: This file contains the JavaScript code for handling form submissions and displaying the shortened URLs to the user.

## Installation and Setup
To initialize the project, follow these steps:

1. Clone the repository: `git clone https://github.com/xen/url-shortener.git`
2. Navigate to the project directory: `cd url-shortener`
3. Install dependencies: `npm install`
4. Create a `.env` file in the project root directory and add the following environment variables:
```bash
   PORT=3000 # The port number on which the server will run (default: 3000).
   MONGODB_URI='mongodb://localhost:27017/urlShortener' # The MongoDB connection URI.
   REDIRECT_URL='https://example.com' # The URL to redirect users when they visit the root path.
```
5. Run the application: `npm start`

## Usage
To use the URL Shortener, follow these steps:

1. Open your web browser and navigate to `http://localhost:3000` (or the appropriate port if you've changed it in the `.env` file).
2. Enter the long URL you want to shorten in the input field.
3. Optionally, provide a creator name and expiration date for the shortened URL.
4. Click the "Shorten URL" button to generate the shortened URL.
5. The shortened URL will be displayed on the page, along with a QR code for easy scanning.
6. When users click on the shortened URL, they will be redirected to the original long URL.
7. The application will track analytics data for each shortened URL, such as the number of clicks, last click timestamp, referrer, IP address, and user agent.

## API Endpoints
The URL Shortener provides the following API endpoints:

- **POST `/shorten`**: Creates a new shortened URL.
  - **Request Body**:
    - `originalUrl` (string): The original URL to be shortened. Must start with `http://` or `https://`.
    - `creator` (string, optional): The creator of the URL. Defaults to `'anonymous'` if not provided.
    - `expirationDate` (string, optional): The expiration date of the shortened URL. Must be a valid date string.
  - **Response**:
    - JSON object containing the shortened URL details or an error message.

- **GET `/:shortId`**: Redirects users to the original long URL based on the shortened ID.
  - **Request Parameters**:
    - `shortId` (string): The shortened ID of the URL.
  - **Response**:
    - Redirects to the original long URL or an error message if the shortened URL is not found.

## Rate Limiting
The URL Shortener implements rate limiting to prevent abuse and protect against potential DDoS attacks. The rate limiter is configured to allow each IP address to make a maximum of 100 requests per 15 minutes. If a user exceeds this limit, they will receive a "Too many requests from this IP, please try again later." error message.

## Analytics
The URL Shortener tracks various analytics data for each shortened URL, including:
- Number of clicks
- Last click timestamp
- Referrer
- IP address
- User agent

This information is stored in the `analytics` field of the URL document in the MongoDB database.

## Error Handling
The URL Shortener handles various error scenarios gracefully:
- If a user submits an invalid URL format, the application will return an "Invalid URL format" error message.
- If a shortened URL is not found, the application will return a "URL not found" error message.
- If there is an error connecting to the MongoDB database, the application will log the error and exit.

## MongoDB Connection Handling
The application attempts to connect to MongoDB at startup. If the connection is successful, the server will start and listen on the specified port. If the connection fails, the application will log the error and terminate the process.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
