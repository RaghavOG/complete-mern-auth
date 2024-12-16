
# MERN Vite ShadCN Template

A boilerplate template for creating full-stack applications using the MERN (MongoDB, Express, React, Node.js) stack with Vite for the frontend, along with ShadCN for modern UI components. This template sets up both the frontend and backend, making it easier to start building applications with minimal setup.

## Features

- **Backend:**
  - Express.js server
  - MongoDB integration with Mongoose
  - JWT-based authentication (with `jsonwebtoken`)
  - Secure HTTP headers using Helmet
  - Cookie parsing and CORS handling
  - Modular folder structure for models, routes, controllers, services, and utilities
  - `dotenv` for environment configuration

- **Frontend:**
  - React.js with Vite for fast development and build processes
  - ShadCN for pre-built UI components
  - TailwindCSS for styling
  - Modular structure for easy scaling

- **Development Tools:**
  - Nodemon for automatic backend server restarts during development
  - Linting and basic configurations ready

---

## Prerequisites

Make sure you have the following installed on your machine:

- [Node.js](https://nodejs.org/) (v14.x or higher)
- [Git](https://git-scm.com/)
- MongoDB setup (either local or cloud)

---

## Installation and Setup

### 1. Using the Package

To generate a new MERN project using this template, you can simply run the following command with `npx`:

```bash
npx mern-vite-shadcn-template@latest <your-project-name>
```

This command will:
1. Clone the template repository.
2. Set up the folder structure in the `<your-project-name>` directory.
3. Install dependencies for both frontend and backend.

Example:

```bash
npx mern-vite-shadcn-template my-awesome-app
```

---

### 2. Project Structure

The generated project will have the following structure:

```
my-awesome-app/
├── backend/               # Backend API and logic
│   ├── config/            # Database configurations, constants
│   ├── controllers/       # Controllers for handling requests
│   ├── middlewares/       # Custom middlewares (e.g., authentication)
│   ├── models/            # MongoDB models using Mongoose
│   ├── routes/            # API routes
│   ├── services/          # Business logic or reusable functionalities
│   ├── utils/             # Utility functions
│   └── server.js          # Main Express server file
├── frontend/              # Vite-based React application
│   ├── src/               # Main source code for React app
│   ├── index.html         # Entry point for Vite
│   └── vite.config.js     # Vite configuration
├── .env                   # Environment variables (backend)
├── .gitignore             # Git ignore file
├── README.md              # Project documentation
├── package.json           # Root package file
└── package-lock.json      # Lock file for npm dependencies
```

### 3. Running the Project

After creating your project and navigating to the project folder, follow these steps to start the backend and frontend:

1. **Install dependencies**:

   The command already installs all dependencies, but if needed, you can install manually by running:

   ```bash
   cd <your-project-name>
   npm install --prefix frontend && npm install
   ```

2. **Starting the development servers**:

   - **Backend** (Runs on `http://localhost:5000`):

     ```bash
     npm run dev
     ```

   - **Frontend** (Runs on `http://localhost:3000`):

     ```bash
     cd frontend
     npm run dev
     ```

3. **Building the frontend for production**:

   To build the frontend React app for production:

   ```bash
   cd frontend
   npm run build
   ```

---

## Environment Variables

You’ll need to configure the environment variables in a `.env` file for the backend. An example `.env.sample` file is included.
  
### Sample `.env` File

```bash
PORT=5000
MONGO_URI=""
NODE_ENV=development
JWT_SECRET=your_jwt_secret

CLOUDINARY_NAME=your_cloudinary_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
```

---

## Scripts

Here are some useful npm scripts for managing the project:

- `npm run dev`: Starts the backend server in development mode using `nodemon`.
- `npm run build`: Installs all necessary dependencies and builds the frontend for production.

---

## Issues and Contributions

Feel free to open an issue if you run into problems or have suggestions for improvement. Contributions are welcome!

---

## License

This project is licensed under the [ISC License](./LICENSE).

---

## Acknowledgements

Special thanks to the authors and contributors of the libraries used in this template:

- [Vite](https://vitejs.dev/)
- [React](https://reactjs.org/)
- [Express](https://expressjs.com/)
- [Mongoose](https://mongoosejs.com/)
- [ShadCN](https://shadcn.dev/)

---

## Happy Coding!

