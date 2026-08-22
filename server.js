
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "./models/User.js";
import Order from "./models/Order.js";
import Cart from "./models/Cart.js";

dotenv.config();

const app = express();


// ==========================================
// CONFIGURATION
// ==========================================

const PORT = process.env.PORT || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL ||
  "http://localhost:5173";


// ==========================================
// MIDDLEWARE
// ==========================================

app.use(
  cors({
    origin: CLIENT_URL,
  })
);

app.use(express.json());


// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "ShopSphere API",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
  });
});


// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

function authenticateToken(req, res, next) {
  const authHeader =
    req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {
    return res.status(401).json({
      message: "Authentication required",
    });
  }

  const token =
    authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
}


// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    if (!req.user?.userId) {
      return res.status(401).json({
        message: "Authentication required",
      });
    }

    const user =
      await User.findById(
        req.user.userId
      );

    if (!user) {
      return res.status(401).json({
        message: "User account not found",
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        message: "Admin access required",
      });
    }

    req.admin = user;

    next();
  } catch (error) {
    console.error(
      "Admin authentication error:",
      error
    );

    return res.status(500).json({
      message:
        "Unable to verify admin access",
    });
  }
}


// ==========================================
// REGISTER
// ==========================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          message:
            "Name, email and password are required",
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          message:
            "Password must be at least 6 characters",
        });
      }

      const normalizedEmail =
        email
          .toLowerCase()
          .trim();

      const existingUser =
        await User.findOne({
          email: normalizedEmail,
        });

      if (existingUser) {
        return res.status(409).json({
          message:
            "An account with this email already exists",
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await User.create({
          name: name.trim(),
          email: normalizedEmail,
          password: hashedPassword,
        });

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),
            role: user.role,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

      res.status(201).json({
        message:
          "Account created successfully",

        token,

        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          isEmailVerified:
            user.isEmailVerified,
        },
      });
    } catch (error) {
      console.error(
        "Registration error:",
        error
      );

      res.status(500).json({
        message:
          "Something went wrong while creating your account",
      });
    }
  }
);


// ==========================================
// LOGIN
// ==========================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const {
        email,
        password,
      } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          message:
            "Email and password are required",
        });
      }

      const normalizedEmail =
        email
          .toLowerCase()
          .trim();

      const user =
        await User.findOne({
          email: normalizedEmail,
        });

      if (!user) {
        return res.status(401).json({
          message:
            "Invalid email or password",
        });
      }

      const passwordMatch =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!passwordMatch) {
        return res.status(401).json({
          message:
            "Invalid email or password",
        });
      }

      const token =
        jwt.sign(
          {
            userId:
              user._id.toString(),
            role: user.role,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

      res.json({
        message:
          "Login successful",

        token,

        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          isEmailVerified:
            user.isEmailVerified,
        },
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        message:
          "Something went wrong while logging in",
      });
    }
  }
);


// ==========================================
// GET CURRENT USER
// ==========================================

app.get(
  "/api/auth/me",
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.user.userId
        ).select(
          "_id name email role isEmailVerified createdAt"
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found",
        });
      }

      res.json({
        user,
      });
    } catch (error) {
      console.error(
        "Get current user error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load user",
      });
    }
  }
);


// ==========================================
// GET CART
// ==========================================

app.get(
  "/api/cart",
  authenticateToken,
  async (req, res) => {
    try {
      let cart =
        await Cart.findOne({
          user: req.user.userId,
        });

      if (!cart) {
        cart =
          await Cart.create({
            user: req.user.userId,
            items: [],
          });
      }

      res.json({
        cart,
      });
    } catch (error) {
      console.error(
        "Get cart error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load your cart",
      });
    }
  }
);


// ==========================================
// ADD ITEM TO CART
// ==========================================

app.post(
  "/api/cart/items",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        productId,
        name,
        price,
        image,
        quantity = 1,
      } = req.body;

      if (
        !productId ||
        !name ||
        price === undefined
      ) {
        return res.status(400).json({
          message:
            "Product information is required",
        });
      }

      const numericPrice =
        Number(price);

      const numericQuantity =
        Number(quantity);

      if (
        !Number.isFinite(
          numericPrice
        ) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          message:
            "Invalid product price",
        });
      }

      if (
        !Number.isInteger(
          numericQuantity
        ) ||
        numericQuantity < 1
      ) {
        return res.status(400).json({
          message:
            "Invalid quantity",
        });
      }

      let cart =
        await Cart.findOne({
          user: req.user.userId,
        });

      if (!cart) {
        cart = new Cart({
          user: req.user.userId,
          items: [],
        });
      }

      const existingItem =
        cart.items.find(
          (item) =>
            item.productId ===
            String(productId)
        );

      if (existingItem) {
        existingItem.quantity +=
          numericQuantity;
      } else {
        cart.items.push({
          productId:
            String(productId),

          name: String(name),

          price: numericPrice,

          image: image || "",

          quantity:
            numericQuantity,
        });
      }

      await cart.save();

      res.status(201).json({
        message:
          "Product added to cart",

        cart,
      });
    } catch (error) {
      console.error(
        "Add to cart error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to add product to cart",
      });
    }
  }
);


// ==========================================
// UPDATE CART ITEM
// ==========================================

app.put(
  "/api/cart/items/:productId",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        quantity,
      } = req.body;

      const numericQuantity =
        Number(quantity);

      if (
        !Number.isInteger(
          numericQuantity
        ) ||
        numericQuantity < 1
      ) {
        return res.status(400).json({
          message:
            "Quantity must be at least 1",
        });
      }

      const cart =
        await Cart.findOne({
          user: req.user.userId,
        });

      if (!cart) {
        return res.status(404).json({
          message:
            "Cart not found",
        });
      }

      const item =
        cart.items.find(
          (cartItem) =>
            cartItem.productId ===
            String(
              req.params.productId
            )
        );

      if (!item) {
        return res.status(404).json({
          message:
            "Product not found in cart",
        });
      }

      item.quantity =
        numericQuantity;

      await cart.save();

      res.json({
        message:
          "Cart updated",

        cart,
      });
    } catch (error) {
      console.error(
        "Update cart error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to update cart",
      });
    }
  }
);


// ==========================================
// REMOVE CART ITEM
// ==========================================

app.delete(
  "/api/cart/items/:productId",
  authenticateToken,
  async (req, res) => {
    try {
      const cart =
        await Cart.findOne({
          user: req.user.userId,
        });

      if (!cart) {
        return res.status(404).json({
          message:
            "Cart not found",
        });
      }

      const originalLength =
        cart.items.length;

      cart.items =
        cart.items.filter(
          (item) =>
            item.productId !==
            String(
              req.params.productId
            )
        );

      if (
        cart.items.length ===
        originalLength
      ) {
        return res.status(404).json({
          message:
            "Product not found in cart",
        });
      }

      await cart.save();

      res.json({
        message:
          "Product removed from cart",

        cart,
      });
    } catch (error) {
      console.error(
        "Remove cart item error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to remove product from cart",
      });
    }
  }
);


// ==========================================
// CLEAR CART
// ==========================================

app.delete(
  "/api/cart",
  authenticateToken,
  async (req, res) => {
    try {
      let cart =
        await Cart.findOne({
          user: req.user.userId,
        });

      if (!cart) {
        cart =
          await Cart.create({
            user: req.user.userId,
            items: [],
          });
      } else {
        cart.items = [];

        await cart.save();
      }

      res.json({
        message:
          "Cart cleared",

        cart,
      });
    } catch (error) {
      console.error(
        "Clear cart error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to clear cart",
      });
    }
  }
);


// ==========================================
// CREATE ORDER
// ==========================================

app.post(
  "/api/orders",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        items,
        shippingAddress,
        paymentMethod,
      } = req.body;

      if (
        !items ||
        !Array.isArray(items) ||
        items.length === 0
      ) {
        return res.status(400).json({
          message:
            "Your order must contain at least one item",
        });
      }

      if (!shippingAddress) {
        return res.status(400).json({
          message:
            "Shipping address is required",
        });
      }

      const requiredFields = [
        "fullName",
        "email",
        "phone",
        "address",
        "city",
        "postalCode",
      ];

      for (
        const field of requiredFields
      ) {
        if (
          !shippingAddress[field] ||
          !String(
            shippingAddress[field]
          ).trim()
        ) {
          return res.status(400).json({
            message:
              `${field} is required`,
          });
        }
      }

      if (
        ![
          "cash_on_delivery",
          "card",
        ].includes(paymentMethod)
      ) {
        return res.status(400).json({
          message:
            "Invalid payment method",
        });
      }

      const cleanedItems =
        items.map((item) => {
          const numericPrice =
            Number(item.price);

          const numericQuantity =
            Number(item.quantity);

          if (
            !item.productId ||
            !item.name ||
            !Number.isFinite(
              numericPrice
            ) ||
            numericPrice < 0 ||
            !Number.isInteger(
              numericQuantity
            ) ||
            numericQuantity < 1
          ) {
            throw new Error(
              "Invalid product information in cart"
            );
          }

          return {
            productId:
              String(
                item.productId
              ),

            name:
              String(item.name),

            price:
              numericPrice,

            image:
              item.image || "",

            quantity:
              numericQuantity,
          };
        });

      const subtotal =
        cleanedItems.reduce(
          (total, item) =>
            total +
            item.price *
              item.quantity,
          0
        );

      const shippingCost =
        subtotal >= 100
          ? 0
          : 5;

      const total =
        subtotal +
        shippingCost;

      const order =
        await Order.create({
          user:
            req.user.userId,

          items:
            cleanedItems,

          shippingAddress: {
            fullName:
              shippingAddress.fullName.trim(),

            email:
              shippingAddress.email
                .toLowerCase()
                .trim(),

            phone:
              shippingAddress.phone.trim(),

            address:
              shippingAddress.address.trim(),

            city:
              shippingAddress.city.trim(),

            postalCode:
              shippingAddress.postalCode.trim(),
          },

          paymentMethod,

          paymentStatus:
            "pending",

          orderStatus:
            "pending",

          subtotal,

          shippingCost,

          total,
        });

      console.log(
        `🛍️ New order created: ${order._id}`
      );

      res.status(201).json({
        message:
          "Order placed successfully",

        order,
      });
    } catch (error) {
      console.error(
        "Create order error:",
        error
      );

      res.status(500).json({
        message:
          error.message ||
          "Something went wrong while creating the order",
      });
    }
  }
);


// ==========================================
// GET MY ORDERS
// ==========================================

app.get(
  "/api/orders",
  authenticateToken,
  async (req, res) => {
    try {
      const orders =
        await Order.find({
          user:
            req.user.userId,
        }).sort({
          createdAt: -1,
        });

      res.json({
        orders,
      });
    } catch (error) {
      console.error(
        "Get orders error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load your orders",
      });
    }
  }
);


// ==========================================
// GET SINGLE ORDER
// ==========================================

app.get(
  "/api/orders/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const order =
        await Order.findOne({
          _id: req.params.id,

          user:
            req.user.userId,
        });

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found",
        });
      }

      res.json({
        order,
      });
    } catch (error) {
      console.error(
        "Get order error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load the order",
      });
    }
  }
);


// =====================================================
// =====================================================
// ADMIN API
// =====================================================
// =====================================================


// ==========================================
// ADMIN CHECK
// ==========================================

app.get(
  "/api/admin/me",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    res.json({
      admin: {
        id:
          req.admin._id,

        name:
          req.admin.name,

        email:
          req.admin.email,

        role:
          req.admin.role,
      },
    });
  }
);


// ==========================================
// ADMIN DASHBOARD STATISTICS
// ==========================================

app.get(
  "/api/admin/dashboard",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalOrders,
        pendingOrders,
        processingOrders,
        shippedOrders,
        deliveredOrders,
        cancelledOrders,
      ] =
        await Promise.all([
          User.countDocuments(),

          Order.countDocuments(),

          Order.countDocuments({
            orderStatus:
              "pending",
          }),

          Order.countDocuments({
            orderStatus:
              "processing",
          }),

          Order.countDocuments({
            orderStatus:
              "shipped",
          }),

          Order.countDocuments({
            orderStatus:
              "delivered",
          }),

          Order.countDocuments({
            orderStatus:
              "cancelled",
          }),
        ]);

      const orders =
        await Order.find().select(
          "total paymentStatus orderStatus createdAt"
        );

      const revenue =
        orders.reduce(
          (total, order) =>
            total +
            Number(
              order.total || 0
            ),
          0
        );

      const paidRevenue =
        orders
          .filter(
            (order) =>
              order.paymentStatus ===
              "paid"
          )
          .reduce(
            (total, order) =>
              total +
              Number(
                order.total || 0
              ),
            0
          );

      res.json({
        statistics: {
          totalUsers,
          totalOrders,

          pendingOrders,
          processingOrders,
          shippedOrders,
          deliveredOrders,
          cancelledOrders,

          revenue,
          paidRevenue,
        },
      });
    } catch (error) {
      console.error(
        "Admin dashboard error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load admin dashboard",
      });
    }
  }
);


// ==========================================
// ADMIN GET ALL USERS
// ==========================================

app.get(
  "/api/admin/users",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .select(
            "_id name email role isEmailVerified createdAt"
          )
          .sort({
            createdAt: -1,
          });

      res.json({
        users,
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load users",
      });
    }
  }
);


// ==========================================
// ADMIN GET SINGLE USER
// ==========================================

app.get(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.id
        ).select(
          "_id name email role isEmailVerified createdAt"
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found",
        });
      }

      res.json({
        user,
      });
    } catch (error) {
      console.error(
        "Admin single user error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load user",
      });
    }
  }
);


// ==========================================
// ADMIN CHANGE USER ROLE
// ==========================================

app.put(
  "/api/admin/users/:id/role",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        role,
      } = req.body;

      if (
        ![
          "user",
          "admin",
        ].includes(role)
      ) {
        return res.status(400).json({
          message:
            "Invalid role",
        });
      }

      if (
        String(
          req.admin._id
        ) ===
        String(
          req.params.id
        ) &&
        role !== "admin"
      ) {
        return res.status(400).json({
          message:
            "You cannot remove your own admin access",
        });
      }

      const user =
        await User.findByIdAndUpdate(
          req.params.id,
          {
            role,
          },
          {
            new: true,
            runValidators: true,
          }
        ).select(
          "_id name email role isEmailVerified createdAt"
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found",
        });
      }

      res.json({
        message:
          "User role updated successfully",

        user,
      });
    } catch (error) {
      console.error(
        "Admin role update error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to update user role",
      });
    }
  }
);


// ==========================================
// ADMIN DELETE USER
// ==========================================

app.delete(
  "/api/admin/users/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      if (
        String(
          req.admin._id
        ) ===
        String(
          req.params.id
        )
      ) {
        return res.status(400).json({
          message:
            "You cannot delete your own admin account",
        });
      }

      const user =
        await User.findByIdAndDelete(
          req.params.id
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found",
        });
      }

      await Cart.deleteOne({
        user:
          req.params.id,
      });

      res.json({
        message:
          "User deleted successfully",
      });
    } catch (error) {
      console.error(
        "Admin delete user error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to delete user",
      });
    }
  }
);


// ==========================================
// ADMIN GET ALL ORDERS
// ==========================================

app.get(
  "/api/admin/orders",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const orders =
        await Order.find()
          .populate(
            "user",
            "name email"
          )
          .sort({
            createdAt: -1,
          });

      res.json({
        orders,
      });
    } catch (error) {
      console.error(
        "Admin orders error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load orders",
      });
    }
  }
);


// ==========================================
// ADMIN GET SINGLE ORDER
// ==========================================

app.get(
  "/api/admin/orders/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const order =
        await Order.findById(
          req.params.id
        ).populate(
          "user",
          "name email"
        );

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found",
        });
      }

      res.json({
        order,
      });
    } catch (error) {
      console.error(
        "Admin single order error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load order",
      });
    }
  }
);


// ==========================================
// ADMIN UPDATE ORDER STATUS
// ==========================================

app.put(
  "/api/admin/orders/:id/status",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        orderStatus,
      } = req.body;

      const allowedStatuses = [
        "pending",
        "processing",
        "shipped",
        "delivered",
        "completed",
        "cancelled",
      ];

      if (
        !allowedStatuses.includes(
          orderStatus
        )
      ) {
        return res.status(400).json({
          message:
            "Invalid order status",
        });
      }

      const order =
        await Order.findByIdAndUpdate(
          req.params.id,
          {
            orderStatus,
          },
          {
            new: true,
            runValidators: true,
          }
        );

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found",
        });
      }

      res.json({
        message:
          "Order status updated successfully",

        order,
      });
    } catch (error) {
      console.error(
        "Admin order status error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to update order status",
      });
    }
  }
);


// ==========================================
// ADMIN UPDATE PAYMENT STATUS
// ==========================================

app.put(
  "/api/admin/orders/:id/payment-status",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        paymentStatus,
      } = req.body;

      const allowedStatuses = [
        "pending",
        "paid",
        "failed",
        "refunded",
      ];

      if (
        !allowedStatuses.includes(
          paymentStatus
        )
      ) {
        return res.status(400).json({
          message:
            "Invalid payment status",
        });
      }

      const order =
        await Order.findByIdAndUpdate(
          req.params.id,
          {
            paymentStatus,
          },
          {
            new: true,
            runValidators: true,
          }
        );

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found",
        });
      }

      res.json({
        message:
          "Payment status updated successfully",

        order,
      });
    } catch (error) {
      console.error(
        "Admin payment status error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to update payment status",
      });
    }
  }
);


// ==========================================
// ADMIN DELETE ORDER
// ==========================================

app.delete(
  "/api/admin/orders/:id",
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const order =
        await Order.findByIdAndDelete(
          req.params.id
        );

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found",
        });
      }

      res.json({
        message:
          "Order deleted successfully",
      });
    } catch (error) {
      console.error(
        "Admin delete order error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to delete order",
      });
    }
  }
);


// ==========================================
// ADMIN SETUP
// ==========================================
//
// This endpoint is protected by a secret
// stored in .env.
//
// IMPORTANT:
// Add ADMIN_SETUP_KEY to your .env before
// using this endpoint.
//
// Example:
// ADMIN_SETUP_KEY=your-private-secret
//
// This lets you promote your existing
// ShopSphere account to admin without
// creating a public "make admin" endpoint.
//

app.post(
  "/api/admin/setup",
  async (req, res) => {
    try {
      const {
        setupKey,
        email,
      } = req.body;

      if (
        !process.env.ADMIN_SETUP_KEY
      ) {
        return res.status(500).json({
          message:
            "ADMIN_SETUP_KEY is not configured in .env",
        });
      }

      if (
        !setupKey ||
        setupKey !==
          process.env.ADMIN_SETUP_KEY
      ) {
        return res.status(403).json({
          message:
            "Invalid admin setup key",
        });
      }

      if (!email) {
        return res.status(400).json({
          message:
            "Email is required",
        });
      }

      const normalizedEmail =
        email
          .toLowerCase()
          .trim();

      const user =
        await User.findOne({
          email: normalizedEmail,
        });

      if (!user) {
        return res.status(404).json({
          message:
            "No account exists with this email",
        });
      }

      user.role = "admin";

      await user.save();

      res.json({
        message:
          "Admin account created successfully",

        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      console.error(
        "Admin setup error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to create admin account",
      });
    }
  }
);


// ==========================================
// SERVER START
// ==========================================

async function startServer() {
  try {
    if (
      !process.env.MONGODB_URI
    ) {
      throw new Error(
        "MONGODB_URI is missing from .env"
      );
    }

    if (
      !process.env.JWT_SECRET
    ) {
      throw new Error(
        "JWT_SECRET is missing from .env"
      );
    }

    await mongoose.connect(
      process.env.MONGODB_URI
    );

    console.log(
      "✅ MongoDB connected successfully"
    );

    app.listen(
      PORT,
      () => {
        console.log(
          `🚀 ShopSphere API running on ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "❌ MongoDB connection failed:"
    );

    console.error(
      error.message
    );

    process.exit(1);
  }
}

startServer();

