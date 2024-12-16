import { fileURLToPath } from 'url';
import path from 'path';
import multer from 'multer';

// Define __dirname in ES module context
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const storage = multer.memoryStorage();  // Store the file in memory


const upload = multer({ storage: storage });

export default upload;