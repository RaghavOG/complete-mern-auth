import { v2 as Cloudinary } from "cloudinary";
import fs from "fs/promises";
import os from "os";
import path from "path";

Cloudinary.config({
  cloud_name: "dpdzfqj2u",
  api_key: "434784266544154",
  api_secret: "rK3NwosBTZAS5wSurqOut4tewuw",
});

async function CloudinaryUpload(file, folder,filename) {
  try {
    if (!file) throw new Error("No file provided");

    const tempDir = os.tmpdir();
    const tempFilePath = path.join(tempDir, file.originalname);  

    const buffer = Buffer.from(await file.buffer);
    await fs.writeFile(tempFilePath, buffer);

    const mimeType = file.mimetype;
    
    let resourceType = "auto";

    if (mimeType.startsWith("image/")) {
      resourceType = "image";
    } else if (mimeType.startsWith("video/")) {
      resourceType = "video";
    } else if (mimeType === "application/pdf") {
      resourceType = "raw";
    }

    // Upload the file to Cloudinary
    const response = await Cloudinary.uploader.upload(tempFilePath, {
      resource_type: resourceType,
      flags: "attachment", 
      folder: folder,
      public_id: filename,  
      access_mode: "public",  
    });

    // console.log("File uploaded to Cloudinary successfully:", response);

    await fs.unlink(tempFilePath);

    return response;
  } catch (error) {
    console.error("Error during Cloudinary upload:", error);
    throw error;
  }
}

export { CloudinaryUpload };