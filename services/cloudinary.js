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


    await fs.unlink(tempFilePath);

    return response;
  } catch (error) {
    console.error("Error during Cloudinary upload:", error);
    throw error;
  }
}


const deleteProfilePicture = async (profilePicUrl) => {
  const defaultPicUrl = "https://img.freepik.com/free-vector/businessman-character-avatar-isolated_24877-60111.jpg?t=st=1734246128~exp=1734249728~hmac=929022529bceefc2aa41c6ff3620b5a3efa37489cab55d29e1a5d8846a937ac3&w=740"
  if (profilePicUrl && profilePicUrl !== defaultPicUrl) {
      try {
          const publicId = profilePicUrl.split('/').slice(-2).join('/').split('.')[0]; // Extract publicId
          await Cloudinary.uploader.destroy(publicId); // Delete image in Cloudinary
          console.log("Profile picture deleted successfully.");
      } catch (error) {
          console.error("Error deleting profile picture:", error.message);
          throw new Error("Failed to delete profile picture from Cloudinary.");
      }
  } else {
      console.log("No custom profile picture to delete.");
  }
};

export { CloudinaryUpload  , deleteProfilePicture };