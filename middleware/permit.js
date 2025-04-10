export const roles = {
  admin: ["create:post", "read:post", "update:post", "delete:post"],
  editor: ["create:post", "read:post", "update:post"],
  viewer: [],
};

export function permit(...allowedPermissions) {
  return (req, res, next) => {
    const userRole = req.user.role;
    const permissions = roles[userRole] || [];

    const hasPermission = allowedPermissions.every((perm) =>
      permissions.includes(perm)
    );

    if (!hasPermission) {
      return res.status(403).json({ message: "Access Denied" });
    }

    next();
  };
}
