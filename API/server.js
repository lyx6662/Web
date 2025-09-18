const express = require('express');
const cors = require('cors');
const pool = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const https = require('https');
const fs = require('fs');
const axios = require('axios');
const OSS = require('ali-oss');
const { log } = require('console');
const si = require('systeminformation');
const cron = require('node-cron'); // 新增：任务调度库
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone');

dayjs.extend(utc);
dayjs.extend(timezone);

require('dotenv').config();
const app = express();
const ossClient = new OSS({
  region: process.env.OSS_REGION,
  accessKeyId: process.env.ALIBABA_CLOUD_ACCESS_KEY_ID,
  accessKeySecret: process.env.ALIBABA_CLOUD_ACCESS_KEY_SECRET,
  bucket: process.env.OSS_BUCKET,
  secure: true // 强制HTTPS
});
// 使用更完善的CORS配置
app.use(cors({
  origin: '*', // 在生产环境中建议替换为您的前端域名
  methods: 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
  allowedHeaders: 'Content-Type, Authorization',
}));
app.use(express.json());

//地图辅助函数
const getCoordinatesForDevice = async (deviceData) => {
  const { province, city, location } = deviceData;
  const keywords = `${province || ''}${city || ''}${location || ''}`;

  if (!keywords) {
    console.log('地址信息为空，跳过地理编码。');
    return null;
  }

  if (!process.env.AMAP_WEB_KEY) {
    console.warn('高德地图AMAP_WEB_KEY未配置，无法获取经纬度。');
    return null;
  }

  try {
    console.log(`正在为地址请求地理编码: ${keywords}`);
    const response = await axios.get('https://restapi.amap.com/v3/place/text', {
      params: {
        key: process.env.AMAP_WEB_KEY,
        keywords: keywords,
        city: city || province, // 优先使用城市名作为搜索范围
        extensions: 'base',
        output: 'json'
      }
    });

    // 检查高德API的返回结果是否成功且包含 poi 信息
    if (response.data && response.data.status === '1' && response.data.pois && response.data.pois.length > 0) {
      console.log(`地理编码成功，找到 ${response.data.pois.length} 个可能的位置。`);
      // 返回整个 pois 数组，让调用者决定如何处理
      return response.data.pois; 
    } else {
      console.warn(`高德API未能解析地址: ${keywords}. 原因: ${response.data.info}`);
      return null;
    }
  } catch (error) {
    console.error('调用高德地图API时出错:', error.response?.data || error.message);
    return null;
  }
};
// 认证中间件 (建议创建一个单独的文件)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};
// ************************************************************************************************************
// 模块 A: 用户认证与个人信息 (User Auth & Profile)
// ************************************************************************************************************

// 用户注册
app.post('/api/auth/register', async (req, res) => {
  console.log('注册请求收到:', req.body);
  const { username, account, password, email, address, phone } = req.body;

  // 验证输入
  if (!username || !account || !password || !phone) {
    return res.status(400).json({ error: '必填字段不能为空' });
  }

  try {
    // 检查用户名或账号是否已存在
    const [existingUsers] = await pool.query(
      'SELECT user_id FROM users WHERE username = ? OR account = ? OR phone = ?',
      [username, account, phone]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({ error: '用户名、账号或手机号已存在' });
    }

    // 哈希密码
    const passwordHash = await bcrypt.hash(password, 10);

    // 创建新用户
    const [result] = await pool.query(
      'INSERT INTO users (username, account, password, email, address, phone) VALUES (?, ?, ?, ?, ?, ?)',
      [username, account, passwordHash, email, address, phone]
    );

    // 生成JWT Token
    const token = jwt.sign(
      { userId: result.insertId },
      process.env.JWT_SECRET || 'your_secret_key',
      { expiresIn: '1h' }
    );

    res.status(201).json({
      token,
      user: {
        userId: result.insertId,
        username,
        account,
        email,
        phone
      }
    });
  } catch (err) {
    console.error('注册失败:', err);
    res.status(500).json({ error: '注册失败' });
  }
});

// 用户登录
app.post('/api/auth/login', async (req, res) => {
  const { account, password } = req.body;

  if (!account || !password) {
    return res.status(400).json({ error: '账号和密码不能为空' });
  }

  try {
    // 查找用户
    const [users] = await pool.query(
      'SELECT user_id, username, account, password FROM users WHERE account = ?',
      [account]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: '账号或密码错误' });
    }

    const user = users[0];

    // 验证密码
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: '账号或密码错误' });
    }

    // 生成JWT Token
    const token = jwt.sign(
      { userId: user.user_id },
      process.env.JWT_SECRET || 'your_secret_key',
      { expiresIn: '12h' }
    );

    res.json({
      token,
      user: {
        userId: user.user_id,
        username: user.username,
        account: user.account
      }
    });
  } catch (err) {
    console.error('登录失败:', err);
    res.status(500).json({ error: '登录失败' });
  }
});

// 获取用户个人信息
app.get('/api/user/profile', async (req, res) => {
  try {
    // 从Authorization头部获取token
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }

    // 验证并解码token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;

    // 查询用户信息
    const [users] = await pool.query(
      'SELECT user_id, username, account, email, address, phone, create_time FROM users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }

    res.json(users[0]);
  } catch (err) {
    console.error('获取用户信息失败:', err);

    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: '无效的令牌' });
    }

    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌已过期' });
    }

    res.status(500).json({ error: '获取用户信息失败' });
  }
});

// 修改密码
app.post('/api/user/change-password', async (req, res) => {
  try {
    // 验证token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;
    const { currentPassword, newPassword } = req.body;

    // 验证输入
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: '当前密码和新密码不能为空' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: '新密码长度至少为6位' });
    }

    // 获取当前用户密码
    const [users] = await pool.query(
      'SELECT password FROM users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }

    // 验证当前密码
    const isValid = await bcrypt.compare(currentPassword, users[0].password);
    if (!isValid) {
      return res.status(401).json({ error: '当前密码不正确' });
    }

    // 更新密码
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password = ? WHERE user_id = ?',
      [newPasswordHash, userId]
    );

    res.json({ success: true, message: '密码修改成功' });
  } catch (err) {
    console.error('修改密码失败:', err);

    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: '无效的令牌' });
    }

    res.status(500).json({ error: '修改密码失败' });
  }
});

// 更新用户个人信息接口
app.post('/api/user/update-profile', async (req, res) => {
  try {
    // 从Authorization头部获取token
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }

    // 验证并解码token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;

    // 获取要更新的字段
    const { username, email, address, phone } = req.body;

    // 验证至少提供了一个可更新字段
    if (!username && !email && !address && !phone) {
      return res.status(400).json({ error: '至少提供一个要更新的字段' });
    }

    // 验证手机号格式（如果提供了手机号）
    if (phone) {
      const phoneRegex = /^1[3-9]\d{9}$/; // 简单的中国大陆手机号验证
      if (!phoneRegex.test(phone)) {
        return res.status(400).json({ error: '手机号格式不正确' });
      }
    }

    // 验证邮箱格式（如果提供了邮箱）
    if (email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: '邮箱格式不正确' });
      }
    }

    // 检查手机号是否已被其他用户使用
    if (phone) {
      const [existingPhone] = await pool.query(
        'SELECT user_id FROM users WHERE phone = ? AND user_id != ?',
        [phone, userId]
      );
      if (existingPhone.length > 0) {
        return res.status(400).json({ error: '该手机号已被其他用户使用' });
      }
    }

    // 构建更新语句
    const updateFields = [];
    const updateValues = [];

    if (username) {
      updateFields.push('username = ?');
      updateValues.push(username);
    }
    if (email) {
      updateFields.push('email = ?');
      updateValues.push(email);
    }
    if (address) {
      updateFields.push('address = ?');
      updateValues.push(address);
    }
    if (phone) {
      updateFields.push('phone = ?');
      updateValues.push(phone);
    }

    // 添加用户ID作为WHERE条件
    updateValues.push(userId);

    // 执行更新
    const [result] = await pool.query(
      `UPDATE users SET ${updateFields.join(', ')} WHERE user_id = ?`,
      updateValues
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '用户不存在或未做任何更改' });
    }

    // 获取更新后的用户信息
    const [users] = await pool.query(
      'SELECT user_id, username, account, email, address, phone, create_time FROM users WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      message: '个人信息更新成功',
      user: users[0]
    });

  } catch (err) {
    console.error('更新个人信息失败:', err);

    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: '无效的令牌' });
    }

    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌已过期' });
    }

    res.status(500).json({ error: '更新个人信息失败', details: err.message });
  }
});

// 获取用户个性化设置
app.get('/api/user/settings', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未提供令牌' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;

    // 查找用户设置，若无则返回默认值
    const [settings] = await pool.query(
      'SELECT theme_mode FROM user_settings WHERE user_id = ?',
      [userId]
    );

    if (settings.length === 0) {
      // 返回默认设置
      return res.json({
        theme_mode: 'light'
      });
    }

    res.json(settings[0]);
  } catch (err) {
    console.error('获取设置失败:', err);
    res.status(500).json({ error: '获取设置失败' });
  }
});

// 更新用户个性化设置
app.put('/api/user/settings', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未提供令牌' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;
    const { theme_mode } = req.body;

    // 检查是否已有设置，有则更新，无则插入
    const [existing] = await pool.query(
      'SELECT * FROM user_settings WHERE user_id = ?',
      [userId]
    );

    if (existing.length > 0) {
      // 更新现有设置
      await pool.query(
        `UPDATE user_settings SET 
         theme_mode = ?,
         updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ?`,
        [theme_mode, userId]
      );
    } else {
      // 插入新设置
      await pool.query(
        `INSERT INTO user_settings 
         (user_id, theme_mode)
         VALUES (?, ?)`,
        [userId, theme_mode]
      );
    }

    res.json({ success: true, message: '设置已保存' });
  } catch (err) {
    console.error('更新设置失败:', err);
    res.status(500).json({ error: '更新设置失败' });
  }
});

// ************************************************************************************************************
// 模块 B: 摄像头设备管理 (摄像头设备)
// ************************************************************************************************************


// 获取用户设备信息
app.get('/api/devices', async (req, res) => {
  try {
    const userId = req.query.user_id; // 从查询参数获取用户ID

    let query = `
      SELECT d.device_id, d.device_name, d.device_code, d.push_url, d.pull_url, 
             d.province, d.city, d.location, d.coordinates, d.status, d.install_time,
             u.user_id, u.username, u.account
      FROM devices d
      JOIN users u ON d.user_id = u.user_id
    `;

    let params = [];

    // 如果有传入用户ID，则添加筛选条件
    if (userId) {
      query += ' WHERE d.user_id = ?';
      params.push(userId);
    }

    const [devices] = await pool.query(query, params);

    res.json(devices);
  } catch (err) {
    console.error('获取设备列表失败:', err);
    res.status(500).json({ error: '获取设备列表失败' });
  }
});

// 获取播流地址
app.post('/api/devices/stream-url', async (req, res) => {
  const { device_code } = req.body;

  try {
    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device/start-push-rtmp-stream?device-code=${device_code}&duration=6000&chann=1&codec=1`
    );

    if (response.data.code === 0) {
      res.json({
        message: '播流地址获取成功',
        streamUrl: response.data.data
      });
    } else {
      throw new Error(response.data.message || "获取播流地址失败");
    }
  } catch (err) {
    console.error('获取播流地址失败:', err);
    res.status(500).json({ error: '获取播流地址失败: ' + (err.response?.data?.message || err.message) });
  }
});

// 关闭播流接口
app.post('/api/devices/stop-stream', async (req, res) => {
  const { deviceCode } = req.body;

  if (!deviceCode) {
    return res.status(400).json({ error: '设备代码不能为空' });
  }

  try {
    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device/stop-push-rtmp-stream?device-code=${deviceCode}`
    );

    if (response.data.code === 0) {
      res.json({
        success: true,
        message: '播流已成功关闭'
      });
    } else {
      res.status(500).json({
        error: '关闭播流失败: ' + (response.data.message || '未知错误')
      });
    }
  } catch (error) {
    console.error('关闭播流出错:', error);
    res.status(500).json({
      error: '关闭播流失败: ' + (error.response?.data?.error || error.message)
    });
  }
});

// 添加新设备
app.post('/api/devices', async (req, res) => {
  const {
    device_name,
    device_code,
    province,
    city,
    location,
    user_id,
    install_time,
    coordinates 
  } = req.body;

  // 1. 严格验证必填字段
  if (!device_name || !device_code || !user_id) {
    return res.status(400).json({ error: '设备类型、代码和用户ID不能为空' });
  }

  try {

    let finalCoordinates = null;

    // 3. 决定如何获取坐标
    if (coordinates) {
      // 场景A: 前端已传入明确的坐标。
      // 这通常发生在第一次提交返回了多个地址选项，用户选择后前端再次提交。
      console.log(`接收到前端指定的坐标: ${coordinates}`);
      finalCoordinates = coordinates;
    } else {
      // 场景B: 前端未提供坐标，需要后端调用API查询。
      const locations = await getCoordinatesForDevice(req.body);

      if (locations && locations.length > 1) {
        // 关键逻辑: 发现多个可能的地址，返回400错误和选项列表给前端
        console.log('发现多个地址，请求用户选择。');
        return res.status(400).json({
          error: '发现多个可能的地址，请选择一个确切的位置。',
          // 格式化数据，只返回前端需要的信息
          choices: locations.map(poi => ({
            id: poi.id,
            name: `${poi.name} (${poi.adname})`,
            address: poi.address,
            location: poi.location // "经度,纬度"
          }))
        });
      } else if (locations && locations.length === 1) {
        // 只有一个匹配地址，自动使用
        finalCoordinates = locations[0].location;
        console.log(`自动确定坐标: ${finalCoordinates}`);
      } else {
        // 没有找到地址或API出错，坐标存为 null
        console.log('未找到地址坐标。');
        finalCoordinates = null;
      }
    }

    // 4. 将所有数据插入数据库
    const [result] = await pool.query(
      `INSERT INTO devices 
       (device_name, device_code, province, city, location, coordinates, user_id, install_time, push_url, pull_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        device_name,
        device_code,
        province || null,
        city || null,
        location || null,
        finalCoordinates, // 插入最终确定的坐标
        user_id,
        install_time ? new Date(install_time) : new Date(),
        "未设置",
        "播流地址还没开放"
      ]
    );

    // 5. 返回成功响应
    res.status(201).json({
      success: true,
      message: '设备添加成功',
      data: { deviceId: result.insertId }
    });
  } catch (err) {
    console.error('添加设备失败:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: '设备代码已存在' });
    }
    res.status(500).json({ error: '添加设备失败' });
  }
});


// 更新设备信息
app.put('/api/devices/:id', async (req, res) => {
  const deviceId = req.params.id;
  const {
    device_name,
    device_code,
    province,
    city,
    location,
    status,
    push_url,
    pull_url,
    // 同样，这个字段用于接收用户从多地址选项中选择的结果
    coordinates 
  } = req.body;

  try {
    // 1. 检查设备是否存在，并获取旧数据
    const [existingDeviceResult] = await pool.query(
      'SELECT * FROM devices WHERE device_id = ?',
      [deviceId]
    );
    if (existingDeviceResult.length === 0) {
      return res.status(404).json({ error: '目标设备不存在' });
    }
    const existingDevice = existingDeviceResult[0];

    // 2. 若设备代码有变更，检查唯一性 (此处省略，假设您已有此逻辑)
    // ...

    let finalCoordinates = existingDevice.coordinates; // 默认使用旧坐标
    
    // 3. 检查地址信息是否发生变化
    const addressChanged = existingDevice.province !== province || existingDevice.city !== city || existingDevice.location !== location;

    if (coordinates) {
        // 场景A: 前端传入了明确的坐标。
        // 这意味着地址被修改，且第一次提交返回了多选项，现在用户已选定。
        console.log(`接收到前端为更新操作指定的坐标: ${coordinates}`);
        finalCoordinates = coordinates;
    } else if (addressChanged) {
        // 场景B: 地址已变更，且前端未提供坐标，需要后端查询API。
        console.log('设备地址已变更，正在重新获取经纬度...');
        const locations = await getCoordinatesForDevice(req.body);

        if (locations && locations.length > 1) {
            // 关键逻辑: 发现多个可能的地址，返回400错误和选项列表
            console.log('发现多个地址，请求用户选择。');
            return res.status(400).json({
                error: '发现多个可能的地址，请选择一个确切的位置。',
                choices: locations.map(poi => ({
                    id: poi.id,
                    name: `${poi.name} (${poi.adname})`,
                    address: poi.address,
                    location: poi.location
                }))
            });
        }
        
        finalCoordinates = (locations && locations.length === 1) ? locations[0].location : null;
        console.log(`地址变更后，自动确定新坐标: ${finalCoordinates}`);
    }
    // 如果地址未变，finalCoordinates 将保持为 existingDevice.coordinates，不会重新查询。

    // 4. 执行更新操作
    await pool.query(
      `UPDATE devices SET 
       device_name = ?, device_code = ?, province = ?, city = ?, location = ?,
       status = ?, push_url = ?, pull_url = ?, coordinates = ?
       WHERE device_id = ?`,
      [
        device_name, device_code, province, city, location, status,
        push_url, pull_url, finalCoordinates, deviceId
      ]
    );

    // 5. 返回更新结果
    res.json({
      success: true,
      message: '设备信息更新成功',
      data: { deviceId: Number(deviceId) }
    });
  } catch (err) {
    console.error('更新设备失败:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: '更新失败，设备代码重复' });
    }
    res.status(500).json({ error: '更新设备失败' });
  }
});

// 更新设备播流地址
app.put('/api/devices/:id/stream-url', async (req, res) => {
  const deviceId = req.params.id;
  const { pull_url } = req.body;

  if (!pull_url) {
    return res.status(400).json({ error: '缺少播流地址' });
  }

  try {
    const [result] = await pool.query(
      `UPDATE devices SET pull_url = ? WHERE device_id = ?`,
      [pull_url, deviceId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '设备不存在' });
    }

    res.json({ message: '播流地址更新成功', pull_url });
  } catch (err) {
    console.error('更新播流地址失败:', err);
    res.status(500).json({ error: '更新播流地址失败' });
  }
});

// 删除设备
app.delete('/api/devices/:id', async (req, res) => {
  const deviceId = req.params.id;

  try {
    const [result] = await pool.query(
      'DELETE FROM devices WHERE device_id = ?',
      [deviceId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '设备不存在' });
    }

    res.json({ message: '设备删除成功' });
  } catch (err) {
    console.error('删除设备失败:', err);
    res.status(500).json({ error: '删除设备失败' });
  }
});

// 获取设备状态
app.get('/api/devices/:id/status', async (req, res) => {
  const deviceId = req.params.id;
  const { limit = 10 } = req.query;

  try {
    const [statusRecords] = await pool.query(
      `SELECT * FROM device_status 
       WHERE device_id = ? 
       ORDER BY record_time DESC 
       LIMIT ?`,
      [deviceId, parseInt(limit)]
    );

    res.json(statusRecords);
  } catch (err) {
    console.error('获取设备状态失败:', err);
    res.status(500).json({ error: '获取设备状态失败' });
  }
});

// 添加设备状态记录
app.post('/api/devices/:id/status', async (req, res) => {
  const deviceId = req.params.id;
  const {
    danger_level,
    danger_msg,
    image_url,
    video_url
  } = req.body;

  try {
    // 检查设备是否存在
    const [devices] = await pool.query(
      'SELECT device_id FROM devices WHERE device_id = ?',
      [deviceId]
    );
    if (devices.length === 0) {
      return res.status(404).json({ error: '设备不存在' });
    }

    const [result] = await pool.query(
      `INSERT INTO device_status 
       (device_id, danger_level, danger_msg, image_url, video_url, record_time)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        deviceId,
        danger_level || 0,
        danger_msg,
        image_url,
        video_url,
        new Date()  // 记录当前时间
      ]
    );

    res.status(201).json({
      message: '状态记录添加成功',
      statusId: result.insertId
    });
  } catch (err) {
    console.error('添加状态记录失败:', err);
    res.status(500).json({ error: '添加状态记录失败' });
  }
});

// 更新设备状态处理标记
app.patch('/api/status/:id/processed', async (req, res) => {
  const statusId = req.params.id;

  try {
    const [result] = await pool.query(
      'UPDATE device_status SET is_processed = 1 WHERE status_id = ?',
      [statusId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '状态记录不存在' });
    }

    res.json({ message: '状态标记为已处理' });
  } catch (err) {
    console.error('更新状态记录失败:', err);
    res.status(500).json({ error: '更新状态记录失败' });
  }
});

// 1. 获取设备全部图片（带日期筛选）
app.post('/api/picture/get-by-device-code', async (req, res) => {
  try {
    const { day, deviceCode, page, size } = req.query;
    const channel = 1;
    const towerId = 1;
    const userId = 1282;

    // 验证必填参数
    if (!deviceCode || !page || !size) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    // 调用原始接口
    const response = await axios.post(
      `http://47.104.136.74:20443/v1/picture/get-by-device-code?channel=${channel}&day=${day || ''}&device-code=${deviceCode}&tower-id=${towerId}&user-id=${userId}&page=${page}&size=${size}`
    );

    // 返回原始接口的响应
    res.json(response.data);
  } catch (error) {
    console.error('获取设备图片失败:', error);
    res.status(500).json({
      error: '获取设备图片失败',
      details: error.response?.data || error.message
    });
  }
});

// 获取设备视频列表接口
app.post('/api/device-video/get-by-device-code', async (req, res) => {
  try {
    const { day, deviceCode, page, size } = req.body;

    // 验证必填参数
    if (!deviceCode || !page || !size) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    // 构建查询参数
    const params = new URLSearchParams({
      'device-code': deviceCode,
      'day': day || '', // 空字符串表示不按天筛选
      'page': page.toString(),
      'size': size.toString()
    });

    // 调用原始接口
    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device-video/get-by-device-code?${params.toString()}`
    );

    // 返回原始接口的响应
    res.json(response.data);
  } catch (error) {
    console.error('获取设备视频列表失败:', error);
    res.status(500).json({
      error: '获取设备视频列表失败',
      details: error.response?.data || error.message
    });
  }
});

// 4. 设备抓拍//(成功)
app.post('/api/hub/device-snap-by-device-code', async (req, res) => {
  try {
    const { deviceCode } = req.query;
    const userId = 1282;
    const towerId = 1;
    const channel = 1;
    // 验证必填参数
    if (!deviceCode) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/hub/device-snap-by-device-code?user-id=${userId}&tower-id=${towerId}&device-code=${deviceCode}&channel=${channel}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('设备抓拍失败:', error);
    res.status(500).json({
      error: '设备抓拍失败',
      details: error.response?.data || error.message
    });
  }
});

// 2. 获取设备状态//(成功)
app.post('/api/device-params/get-by-device-code', async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device-params/get-by-device-code?code=${code}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('获取设备状态失败:', error);
    res.status(500).json({
      error: '获取设备状态失败',
      details: error.response?.data || error.message
    });
  }
});

// 5. 设备重启//(成功)
app.post('/api/device/restart', async (req, res) => {
  try {
    const { deviceCode } = req.query;

    if (!deviceCode) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device/restart?device-code=${deviceCode}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('设备重启失败:', error);
    res.status(500).json({
      error: '设备重启失败',
      details: error.response?.data || error.message
    });
  }
});

// 云台方向控制接口
app.post('/api/device-preset/rotation/:direction', async (req, res) => {
  try {
    const { direction } = req.params;
    const { device_code } = req.query;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device-preset/rotation?direction=${direction}&device-code=${device_code}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('云台方向控制失败:', error);
    res.status(500).json({
      error: '云台方向控制失败',
      details: error.response?.data || error.message
    });
  }
});

// 云台复位接口
app.post('/api/device-preset/reset', async (req, res) => {
  try {
    const { device_code } = req.query;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device-preset/reset?device-code=${device_code}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('云台复位失败:', error);
    res.status(500).json({
      error: '云台复位失败',
      details: error.response?.data || error.message
    });
  }
});

// 变焦控制接口
app.post('/api/device/decrease/:zoom_type', async (req, res) => {
  try {
    const { zoom_type } = req.params;
    const { device_code } = req.query;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    // 根据变焦类型设置参数
    let value, zoomRate = 1, channel = 1;

    switch (zoom_type) {
      case 'zoom-in':
        value = -20;
        break;
      case 'zoom-out':
        value = 20;
        break;
      case 'zoom-in-max':
        value = -200;
        break;
      case 'zoom-out-max':
        value = 200;
        break;
      default:
        return res.status(400).json({ error: '无效的变焦类型' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device/decrease?device-code=${device_code}&value=${value}&zoom-rate=${zoomRate}&channel=${channel}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('变焦控制失败:', error);
    res.status(500).json({
      error: '变焦控制失败',
      details: error.response?.data || error.message
    });
  }
});

// 加热控制接口
app.post('/api/device/heating-action', async (req, res) => {
  try {
    const { device_code, heating_action = 1 } = req.body;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      'http://47.104.136.74:20443/v1/device/heating-action',
      {
        deviceCode: device_code,
        heatingAction: heating_action
      },
      {
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('加热控制失败:', error);
    res.status(500).json({
      error: '加热控制失败',
      details: error.response?.data || error.message
    });
  }
});

// 雨刮控制接口
app.post('/api/device-preset/wiper', async (req, res) => {
  try {
    const { device_code } = req.query;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/device-preset/wiper?device-code=${device_code}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('雨刮控制失败:', error);
    res.status(500).json({
      error: '雨刮控制失败',
      details: error.response?.data || error.message
    });
  }
});

// 拍摄视频接口
app.post('/api/hub/device-video-by-device-code', async (req, res) => {
  try {
    const { device_code } = req.body;

    if (!device_code) {
      return res.status(400).json({ error: '设备编码不能为空' });
    }

    // 默认参数
    const user_id = 1282;
    const tower_id = 1;
    const channel = 1;

    const response = await axios.post(
      `http://47.104.136.74:20443/v1/hub/device-video-by-device-code?user-id=${user_id}&tower-id=${tower_id}&device-code=${device_code}&channel=${channel}`
    );

    res.json(response.data);
  } catch (error) {
    console.error('拍摄视频失败:', error);
    res.status(500).json({
      error: '拍摄视频失败',
      details: error.response?.data || error.message
    });
  }
});

// 6. 获取报警图片（支持按用户ID筛选）
app.post('/api/alarm/query-early-alarm', async (req, res) => {
  try {
    const { page = 1, size = 1000 } = req.query;
    const { userId } = req.query; // 从查询参数中获取 userId

    // 固定参数
    const orderBy = 'alarm.created_at';
    const order = 'desc';
    const externalApiUserId = 1282; // 访问外部API所用的固定用户ID

    // 验证基础参数
    if (isNaN(Number(page)) || isNaN(Number(size))) {
      return res.status(400).json({ error: 'page和size必须是数字' });
    }

    // ★ 核心逻辑：如果提供了 userId，则进行筛选
    if (userId) {
      // 步骤 1: 从本地数据库获取该用户的所有设备代码
      const [userDevices] = await pool.query(
        'SELECT device_code FROM devices WHERE user_id = ?',
        [userId]
      );

      // 如果用户没有任何设备，直接返回空列表
      if (userDevices.length === 0) {
        return res.json({ code: 0, message: "OK", data: { alarms: [], totalCount: 0 } });
      }
      const userDeviceCodes = new Set(userDevices.map(d => d.device_code));

      // 步骤 2: 从外部API获取所有报警数据（因外部API不支持按设备列表筛选，我们获取足够多的数据在本地处理）
      const params = new URLSearchParams({
        'order-by': orderBy,
        order,
        page: 1,
        size: 2000, // 获取足够多的近期数据进行筛选
        'user-id': externalApiUserId
      });
      const apiUrl = `http://47.104.136.74:20443/v1/alarm/query-early-alarm?${params.toString()}`;
      const response = await axios.post(apiUrl);

      const allAlarms = response.data.data?.alarms || [];

      // 步骤 3: 在服务器端根据用户的设备代码筛选报警信息
      const filteredAlarms = allAlarms.filter(alarm => userDeviceCodes.has(alarm.deviceCode));

      // 步骤 4: 对筛选后的结果进行分页
      const totalCount = filteredAlarms.length;
      const startIndex = (Number(page) - 1) * Number(size);
      const paginatedAlarms = filteredAlarms.slice(startIndex, startIndex + Number(size));

      // 步骤 5: 返回筛选并分页后的结果
      return res.json({
        code: 0,
        message: "OK",
        data: {
          alarms: paginatedAlarms,
          totalCount: totalCount
        }
      });
    }

    // 如果没有提供 userId，则保持原有逻辑不变
    const params = new URLSearchParams({
      'order-by': orderBy,
      order,
      page,
      size,
      'user-id': externalApiUserId
    });
    const apiUrl = `http://47.104.136.74:20443/v1/alarm/query-early-alarm?${params.toString()}`;
    const response = await axios.post(apiUrl);
    res.json(response.data);

  } catch (error) {
    console.error('获取报警图片失败:', {
      params: req.query,
      error: error.message,
      stack: error.stack
    });
    res.status(error.response?.status || 500).json({
      error: '获取报警图片失败',
      details: process.env.NODE_ENV === 'development'
        ? error.response?.data || error.message
        : undefined
    });
  }
});

// 6. 获取报警图片（固定参数版）
app.post('/api/alarm/query-early-alarm', async (req, res) => {
  try {
    const { page = 1, size = 1000 } = req.query; // 只接收page和size参数

    // 固定参数
    const orderBy = 'alarm.created_at';
    const order = 'desc';
    const userId = 1282;

    // 验证必填参数
    if (!page || !size) {
      return res.status(400).json({
        error: '缺少必要参数',
        required: {
          page: 'number (页码)',
          size: 'number (每页数量)'
        },
        defaults: {
          orderBy: 'alarm.created_at',
          order: 'desc',
          userId: 1282
        }
      });
    }

    // 验证参数类型
    if (isNaN(Number(page)) || isNaN(Number(size))) {
      return res.status(400).json({ error: 'page和size必须是数字' });
    }

    // 构建查询参数
    const params = new URLSearchParams({
      'order-by': orderBy,
      order,
      page,
      size,
      'user-id': userId
    });

    const apiUrl = `http://47.104.136.74:20443/v1/alarm/query-early-alarm?${params.toString()}`;
    const response = await axios.post(apiUrl);

    res.json(response.data);
  } catch (error) {
    console.error('获取报警图片失败:', {
      params: req.query,
      error: error.message,
      stack: error.stack
    });

    res.status(error.response?.status || 500).json({
      error: '获取报警图片失败',
      details: process.env.NODE_ENV === 'development'
        ? error.response?.data || error.message
        : undefined
    });
  }
});

// 删除报警接口
app.delete('/api/alarm/alarm/:id', async (req, res) => {
  try {
    // 步骤 1: 验证用户身份 (这是一个很好的安全实践)
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }
    jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');

    // 步骤 2: 从URL参数中获取并验证ID
    const { id } = req.params;
    const alarmId = parseInt(id, 10);

    if (isNaN(alarmId)) {
      return res.status(400).json({ error: '无效的报警ID' });
    }

    // 步骤 3: 构造并调用外部API以执行删除操作
    // 根据您的curl命令，我们知道外部API需要用POST方法并附带固定参数来删除
    const externalApiUrl = 'http://47.104.136.74:20443/v1/alarm/alarm';
    const requestData = {
      type: 4,
      level: 1,
      causes: "8",
      id: alarmId // 使用从URL中获取的ID
    };

    console.log(`[删除请求] 正在调用外部API删除报警 ID: ${alarmId}`, requestData);

    const response = await axios.post(externalApiUrl, requestData, {
      headers: { 'Content-Type': 'application/json' }
    });
    
    // 检查外部API的响应，确保删除成功
    if (response.data.code !== 0) {
        throw new Error(`外部API删除失败: ${response.data.message || '未知错误'}`);
    }

    console.log(`[删除成功] 报警 ID ${alarmId} 已成功删除。`);

    // 步骤 4: 向前端返回成功响应
    res.status(200).json({ message: `报警 ID ${alarmId} 已成功删除。` });

  } catch (error) {
    // 步骤 5: 统一的错误处理
    console.error(`删除报警 ID ${req.params.id} 失败:`, {
      message: error.message,
      apiError: error.response?.data
    });

    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌无效或已过期' });
    }

    res.status(error.response?.status || 500).json({
      error: '删除报警失败',
      details: error.response?.data || error.message
    });
  }
});

// 获取所有设备列表状态 (代理外部服务并自动处理Token)
app.post('/api/devices/query', async (req, res) => {
  try {
    // 步骤1: 自动登录到外部服务获取Token
    console.log('正在登录外部服务以获取Token...');
    const loginResponse = await axios.post(
      'http://47.104.136.74:20443/v1/user/login',
      {
        "username": "quzhoulianyuandianqi",
        "password": "QZLYDQ@2025"
      },
      {
        headers: { 'Content-Type': 'application/json' }
      }
    );

    // 检查登录是否成功并且返回了Token
    if (loginResponse.data.code !== 0 || !loginResponse.data.data.token) {
      console.error('外部服务登录失败:', loginResponse.data.message);
      return res.status(502).json({ 
        error: '无法认证到外部设备服务', 
        details: loginResponse.data.message 
      });
    }

    const token = loginResponse.data.data.token;
    console.log('外部服务Token获取成功。');

    // 步骤2: 使用获取到的Token查询设备列表
    // 从客户端请求的body中获取排序和分页参数，并提供默认值
    const { orderBy = 'created_at', order = 'desc', page = 1, size = 10 } = req.body;

    const queryPayload = {
      orderBy,
      order,
      page: Number(page),
      size: Number(size)
    };
    
    console.log('正在使用Token查询设备列表，参数:', queryPayload);

    const deviceResponse = await axios.post(
      'http://47.104.136.74:20443/v1/device/query',
      queryPayload,
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          // 根据API文档，请求体是JSON，所以使用 application/json 更标准
          'Content-Type': 'application/json' 
        }
      }
    );

    // 步骤3: 将从外部服务获取到的设备列表直接返回给前端
    res.json(deviceResponse.data);

  } catch (error) {
    // 统一处理请求过程中可能发生的任何错误
    console.error('查询设备列表路由出错:', {
      message: error.message,
      responseData: error.response?.data
    });
    res.status(500).json({
      error: '查询外部设备列表失败',
      details: error.response?.data || error.message
    });
  }
});

// ▼▼▼ 核心修改 1: 更新OSS上传接口，增加用户鉴权和动态文件夹 ▼▼▼
app.post('/api/oss/upload', async (req, res) => {
  try {
    // 步骤 1: 从请求头中获取并验证JWT Token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: '未提供认证令牌' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;
    if (!userId) {
      return res.status(401).json({ error: '无效的令牌，缺少用户信息' });
    }
    
    // 步骤 2: 从请求体获取文件名和类型
    const { fileName, fileType } = req.body;
    if (!fileName || !fileType) {
        return res.status(400).json({ error: '缺少文件名或文件类型' });
    }

    // 步骤 3: 根据用户ID生成动态、唯一的对象名称（文件路径）
    // 文件将上传到 "uploads_USERID/timestamp_filename"
    const userUploadsFolder = `uploads_${userId}`;
    const objectName = `${userUploadsFolder}/${Date.now()}_${fileName.replace(/\s+/g, '_')}`;

    // 步骤 4: 生成带签名的上传URL
    const signedUrl = ossClient.signatureUrl(objectName, {
      method: 'PUT',
      'Content-Type': fileType,
      expires: 3600 // 1小时有效
    });

    // 步骤 5: 生成可供访问的URL
    const accessUrl = `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${objectName}`;

    res.json({
      signedUrl,
      accessUrl
    });

  } catch (err) {
    console.error('OSS上传错误:', err);
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌无效或已过期' });
    }
    res.status(500).json({
      error: '文件上传配置失败',
      details: err.message
    });
  }
});

// ▼▼▼ 请用这个最终的、已修正URL编码的版本，替换掉您 server.js 中旧的 /api/oss/files 路由 ▼▼▼
app.get('/api/oss/files', async (req, res) => {
  try {
    // 步骤 1 & 2: 身份验证和参数获取 (保持不变)
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未提供认证令牌' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;
    if (!userId) return res.status(401).json({ error: '无效的令牌，缺少用户信息' });
    const { directory } = req.query;
    if (!directory) return res.status(400).json({ error: '缺少必要的 directory 参数' });
    if (!directory.includes(`_${userId}`)) return res.status(403).json({ error: '无权访问该目录' });

    console.log(`用户 ${userId} 正在请求访问OSS目录: ${directory}`);

    // 步骤 3: 列出文件 (保持不变)
    const result = await ossClient.list({
      prefix: directory,
      delimiter: '/',
      'max-keys': 1000
    });

    // ▼▼▼ 步骤 4: 最终的核心修改 - 构造完全正确的URL ▼▼▼
    const files = (result.objects || []).map(file => {
      // 从完整的 object key 中移除目录前缀，得到纯粹的文件名
      const pureFileName = file.name.replace(directory, '');

      // ★★★ 关键逻辑 ★★★
      // 我们只对这个纯粹的文件名进行双重编码处理
      // 这样就不会错误地编码目录和文件名之间的那个'/'
      const correctlyEncodedFileName = pureFileName
        .split('/')
        .map(part => encodeURIComponent(part))
        .join('%252F');
      
      // 将编码后的目录和编码后的文件名用原始的'/'拼接起来
      const finalPath = directory + correctlyEncodedFileName;
      
      return {
        name: pureFileName,
        // 使用我们手动构造的、编码正确的路径来生成最终URL
        url: `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${finalPath}`,
        lastModified: file.lastModified,
        size: file.size
      };
    });

    res.json(files);
    
  } catch (err) {
    console.error('获取OSS文件列表错误:', err);
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌无效或已过期' });
    }
    res.status(500).json({
      error: '获取文件列表失败',
      details: err.message
    });
  }
});

// ▼▼▼ 核心修改: 更新后的AI视觉检查接口 ▼▼▼
app.post('/api/ai-vision-check', async (req, res) => {
  try {
    // 步骤 1: 验证用户身份
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未提供认证令牌' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
    const userId = decoded.userId;
    if (!userId) return res.status(401).json({ error: '无效的令牌，缺少用户信息' });

    // 步骤 2: 验证请求体 (现在需要 id, imageUrl, cause)
    const { images } = req.body;
    if (!images || !Array.isArray(images) || images.length === 0) {
      return res.status(400).json({ error: '缺少图片数据或格式不正确' });
    }

    // 辅助函数：下载远程图片并返回Buffer
    const downloadImage = async (url) => {
      const response = await axios.get(url, { responseType: 'arraybuffer' });
      return Buffer.from(response.data, 'binary');
    };

    const CAUSES_MAPPING = { '1': '声爆', '2': '烟火', '3': '异物入侵', '4': '飞鸟入侵', '5': '树木生长', '6': '异常放电', '7': '雷电侦测', '8': '大型车辆', '9': '杆塔倾斜', '10': '人员入侵', '11': '鸟巢', '12': '吊车', '13': '塔吊', '14': '翻斗车', '15': '推土机', '16': '水泥泵车', '17': '山火', '18': '烟雾', '19': '挖掘机', '20': '打桩机' };

    // 步骤 3: 遍历所有图片，进行AI处理、备份和删除
    const results = await Promise.all(images.map(async (imageData) => {
      const { id, imageUrl, cause } = imageData;
      try {
        if (!imageUrl || !id) {
          return { id, imageUrl, error: '缺少图片URL或ID', status: 'error' };
        }

        const causeDescriptions = (cause || '').split(',').map(c => CAUSES_MAPPING[c.trim()] || `未知(${c.trim()})`).join('、');

        // 调用AI视觉模型
        const aiResponseData = await axios.post(
          'https://ark.cn-beijing.volces.com/api/v3/chat/completions',
          { model: "doubao-1-5-thinking-vision-pro-250428", messages: [{ role: "user", content: [{ type: "image_url", image_url: { "url": imageUrl } }, { type: "text", text: `请认真观察照片,这是摄像头拍摄识别的照片,框内为摄像头的判断内容,报警引发原因的:"${causeDescriptions}",这次报警是否判断正确？请只回答'是'或'否'。` }] }] },
          { headers: { 'Authorization': `Bearer ${process.env.AI_API_KEY}`, 'Content-Type': 'application/json' } }
        );

        const aiResponse = aiResponseData.data.choices?.[0]?.message?.content || "";
        const isAlarmValid = aiResponse.trim().includes("是");
        console.log(`[AI处理] 图片ID ${id} | AI判断: ${isAlarmValid ? '正确' : '错误'}`);

        // 步骤 4: 如果判断为错误，则执行备份和删除
        if (!isAlarmValid) {
          // 4.1 备份到OSS
          try {
            console.log(`[备份] 准备备份错误图片: ${imageUrl}`);
            const imageBuffer = await downloadImage(imageUrl);
            const urlParts = imageUrl.split('/');
            const originalFileName = urlParts[urlParts.length - 1].split('?')[0];
            const backupFolder = `uploads_错误备份_${userId}`;
            const objectName = `${backupFolder}/${Date.now()}_${originalFileName}`;
            await ossClient.put(objectName, imageBuffer);
            console.log(`[备份成功] 图片ID ${id} 已备份至OSS: ${objectName}`);
          } catch (backupError) {
            console.error(`[备份失败] 图片ID ${id} 备份失败:`, backupError);
            // 备份失败也继续尝试删除，或者根据业务需求决定是否中断
          }

          // 4.2 调用外部API删除记录
          try {
            const externalApiUrl = 'http://47.104.136.74:20443/v1/alarm/alarm';
            const deletePayload = { type: 4, level: 1, causes: "8", id: id };
            const deleteResponse = await axios.post(externalApiUrl, deletePayload, { headers: { 'Content-Type': 'application/json' } });
            if (deleteResponse.data.code !== 0) throw new Error(deleteResponse.data.message);
            console.log(`[删除成功] 报警记录 ID ${id} 已被成功删除。`);
          } catch (deleteError) {
            console.error(`[删除失败] 报警记录 ID ${id} 删除失败:`, deleteError);
            throw new Error('备份成功但删除失败'); // 抛出错误，让前端知道此项处理未完全成功
          }
        }
        
        return { id, imageUrl, cause, isAlarmValid, status: 'success' };
      } catch (error) {
        console.error(`处理图片ID ${id} 时出错:`, error.response?.data || error.message);
        return { id, imageUrl, cause, isAlarmValid: false, error: '处理失败', status: 'error' };
      }
    }));
    
    res.json({ results });

  } catch (err) {
    console.error('批量AI图像识别接口错误:', err);
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌无效或已过期' });
    }
    res.status(500).json({ error: '批量AI图像识别失败', details: err.message });
  }
});


// ************************************************************************************************************
// 模块 C: 变压器局放检测 (GIS Partial Discharge)
// ************************************************************************************************************



// --- API 1: 写入热数据 (供Qt客户端调用) ---
// 简化后的版本，直接使用客户端提供的北京时间字符串
app.post('/api/gis-data/hot', authenticateToken, async (req, res) => {
  // ★★★ 关键日志点 1 ★★★
  console.log(`[HOT_DATA_API_START] Received request to /api-gis-data/hot at ${new Date().toISOString()}`);
  
  const {
    device_id, record_time, pd_peak, pd_average, discharge_pulse_count,
    pd_peak_phase, pd_noise_level, pd_over_threshold, pd_severity,
    discharge_probability, pd_type
  } = req.body;

  // ★★★ 关键日志点 2 ★★★
  console.log('[HOT_DATA_API_BODY] Request Body:', req.body);

  // 验证核心字段是否存在
  if (!device_id || !record_time) {
    console.log('[HOT_DATA_API_FAIL] Validation failed: device_id or record_time is missing.');
    return res.status(400).json({ error: '设备ID和记录时间不能为空' });
  }

  try {
    const sql = `
      INSERT INTO GIS_devices_data_hot (
        device_id, record_time, pd_peak, pd_average, discharge_pulse_count,
        pd_peak_phase, pd_noise_level, pd_over_threshold, pd_severity,
        discharge_probability, pd_type
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    // 【【【 核心变化在这里 】】】
    // 我们不再对 record_time 进行任何转换，直接使用从请求体中获取的值
    const values = [
      device_id, 
      record_time, // ★★★ 直接使用原始的 record_time 字符串
      pd_peak, 
      pd_average, 
      discharge_pulse_count,
      pd_peak_phase, 
      pd_noise_level, 
      pd_over_threshold, 
      pd_severity,
      discharge_probability, 
      pd_type
    ];

    // ★★★ 关键日志点 3 ★★★
    console.log('[HOT_DATA_API_DB] Executing SQL:', sql.replace(/\s+/g, ' '));
    console.log('[HOT_DATA_API_DB] With Values:', values);

    const [result] = await pool.query(sql, values);
    
    // ★★★ 关键日志点 4 ★★★
    console.log(`[HOT_DATA_API_SUCCESS] Data inserted successfully. Insert ID: ${result.insertId}`);
    res.status(201).json({ message: '热数据写入成功' });

  } catch (error) {
    // ★★★ 关键日志点 5 ★★★
    console.error('[HOT_DATA_API_ERROR] Failed to write hot data:', error);
    res.status(500).json({ error: '服务器内部错误', details: error.message });
  }
});


// --- API 2: 读取热数据 (供前端调用) ---
app.get('/api/gis-data/hot', authenticateToken, async (req, res) => {
  const { device_id } = req.query;
  if (!device_id) {
    return res.status(400).json({ error: '必须提供 device_id' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT * FROM GIS_devices_data_hot WHERE device_id = ? ORDER BY record_time DESC LIMIT 1000', // 最多返回最近1000条
      [device_id]
    );
    res.json(rows);
  } catch (error) {
    console.error('读取热数据失败:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// --- API 3: 读取冷数据归档索引 (供前端调用) ---
app.get('/api/gis-data/cold', authenticateToken, async (req, res) => {
  const { device_id, startDate, endDate } = req.query;
  if (!device_id) {
    return res.status(400).json({ error: '必须提供 device_id' });
  }

  try {
    let sql = 'SELECT * FROM GIS_data_archives_2h WHERE device_id = ?';
    const params = [device_id];
    
    if (startDate && endDate) {
      sql += ' AND archive_timestamp BETWEEN ? AND ?';
      params.push(startDate, endDate);
    }
    
    sql += ' ORDER BY archive_timestamp DESC';

    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (error) {
    console.error('读取冷数据索引失败:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});




// ==========================================================
// 【【【 新增API: 手动触发热数据归档到冷数据的任务 】】】
// ==========================================================
app.post('/api/gis-data/archive', authenticateToken, async (req, res) => {
  console.log(`[MANUAL_ARCHIVE_TRIGGER] Received request to archive hot data at ${new Date().toISOString()}`);
  
  try {
    // 直接调用您现有的归档函数
    // 假设 archiveHotData() 函数会返回一些处理结果，例如处理了多少条数据
    const result = await archiveHotData(); 

    // 向前端返回成功信息
    console.log('[MANUAL_ARCHIVE_SUCCESS] Archiving process completed successfully.', result);
    res.status(200).json({ 
        message: '手动归档任务成功完成', 
        details: result // 将归档函数的结果返回
    });

  } catch (error) {
    // 如果归档过程中发生错误，返回500错误
    console.error('[MANUAL_ARCHIVE_ERROR] Failed to manually archive hot data:', error);
    res.status(500).json({ error: '服务器在执行归档任务时发生内部错误', details: error.message });
  }
});



// ************************************************************************************************************
// 模块 D: 微水检测 (Micro Water Detection)
// ************************************************************************************************************



// ************************************************************************************************************
// 模块 E:外部接口调用 (External API Calls)
// ************************************************************************************************************

//获取ai聊天结果
app.post('/api/ai-chat', async (req, res) => {
  try {
    const { messages } = req.body;

    // 验证输入消息长度
    const lastUserMessage = messages.find(m => m.role === 'user');
    if (lastUserMessage && lastUserMessage.content.length > 500) {
      return res.status(400).json({ error: '问题长度不能超过500字符' });
    }

    // 添加系统消息作为第一条消息（如果不存在）
    const formattedMessages = messages[0]?.role === 'system'
      ? messages
      : [
        {
          role: 'system',
          content: '你是人工智能助手。请遵守以下规则：\n' +
            '1. 回答长度不超过1000字符\n' +
            '2. 不讨论政治、暴力、色情等敏感话题\n' +
            '3. 不提供任何违法或有害信息\n' +
            '4. 保持专业和礼貌的态度\n' +
            '5. 如果无法回答，请诚实地告知用户\n' +
            '6. 只回答与电气工程相关的问题，避免其他领域的讨论。\n' +
            '7. 可以回答有关于浙江省衢州市联源电气科技有限公司的相关问题\n'

        },
        ...messages
      ];

    const response = await axios.post(
      process.env.AI_API_URL,
      {
        model: process.env.AI_MODEL,
        messages: formattedMessages,
        max_tokens: 1000 // 限制AI生成的token数量（约等于字符数）
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.AI_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    // 获取AI响应并处理
    let aiResponse = response.data.choices?.[0]?.message?.content || "无响应";

    // 后端二次验证和截断
    if (aiResponse.length > 500) {
      aiResponse = aiResponse.substring(0, 500) + '...';
    }

    // 过滤敏感内容（简单示例）
    const forbiddenWords = ['暴力', '色情', '政治敏感词']; // 替换为实际需要过滤的词
    forbiddenWords.forEach(word => {
      aiResponse = aiResponse.replace(new RegExp(word, 'gi'), '***');
    });

    res.json({
      ...response.data,
      choices: [{
        ...response.data.choices[0],
        message: {
          ...response.data.choices[0].message,
          content: aiResponse
        }
      }]
    });
  } catch (error) {
    console.error('AI接口错误:', error.response?.data || error.message);
    res.status(500).json({
      error: 'AI服务调用失败',
      details: error.response?.data || error.message
    });
  }
});

// 获取验证码接口
app.get('/api/captcha', async (req, res) => {
  try {
    const response = await axios.get('http://shanhe.kim/api/za/yzmv1.php');

    // 将验证码答案存储在服务器内存中（生产环境应该使用Redis等）
    const captchaStore = req.app.get('captchaStore') || {};
    captchaStore[response.data.img] = response.data.answer;
    req.app.set('captchaStore', captchaStore);

    res.json({
      code: 200,
      imgUrl: response.data.img,
      codeText: response.data.codeText
    });
  } catch (error) {
    console.error('获取验证码失败:', error);
    res.status(500).json({ error: '获取验证码失败' });
  }
});

// 验证验证码接口
app.post('/api/verify-captcha', (req, res) => {
  const { imgUrl, userAnswer } = req.body;
  const captchaStore = req.app.get('captchaStore') || {};

  if (!imgUrl || !userAnswer) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  const correctAnswer = captchaStore[imgUrl];

  if (!correctAnswer) {
    return res.status(400).json({ error: '验证码已过期' });
  }

  if (userAnswer.toString() === correctAnswer.toString()) {
    // 验证成功后移除验证码
    delete captchaStore[imgUrl];
    req.app.set('captchaStore', captchaStore);

    return res.json({ success: true });
  } else {
    return res.status(400).json({ error: '验证码错误' });
  }
});

// 获取地图配置信息
app.get('/api/map-config', (req, res) => {
  try {
    res.json({
      amapKey: process.env.AMAP_WEB_KEY,
      plugins: 'AMap.ControlBar,AMap.ToolBar'
    });
  } catch (err) {
    console.error('获取地图配置失败:', err);
    res.status(500).json({ error: '获取地图配置失败' });
  }
});

// 获取服务器状态
app.get('/api/server-stats', async (req, res) => {
  try {
    // 并行获取所有需要的系统信息以提高效率
    const [cpu, mem, fs, net] = await Promise.all([
      si.currentLoad(),   // 获取CPU平均负载
      si.mem(),           // 获取内存使用情况
      si.fsSize(),        // 获取文件系统（磁盘）大小
      si.networkStats()   // 获取网络接口统计
    ]);

    // 筛选出主磁盘（通常是第一个）和主网络接口
    const mainDisk = fs[0] || {};
    const mainNet = net[0] || {};

    // 构造清晰的响应数据结构
    const stats = {
      cpu: {
        // currentLoad 提供了1分钟、5分钟、15分钟的平均负载，我们取第一个
        loadPercent: cpu.currentLoad.toFixed(2), 
      },
      memory: {
        totalBytes: mem.total,
        usedBytes: mem.used,
        // 计算使用率百分比
        usagePercent: ((mem.used / mem.total) * 100).toFixed(2), 
      },
      disk: {
        totalBytes: mainDisk.size,
        usedBytes: mainDisk.used,
        // 使用率百分比
        usagePercent: mainDisk.use.toFixed(2),
      },
      network: {
        // 将字节转换为更易读的 MB
        receivedMb: (mainNet.rx_bytes / 1024 / 1024).toFixed(2),
        sentMb: (mainNet.tx_bytes / 1024 / 1024).toFixed(2),
      }
    };

    res.json(stats);

  } catch (err) {
    console.error('获取服务器状态失败:', err);
    res.status(500).json({ error: '获取服务器状态失败', details: err.message });
  }
});






// ************************************************************************************************************
// 模块 F:定时任务 (Scheduled Tasks)
// ************************************************************************************************************

// --- 定时任务: 每2小时归档热数据到OSS并写入冷数据索引 ---
async function archiveHotData() {
  console.log(`[ARCHIVE_JOB_START] [${new Date().toISOString()}] Starting data archiving task...`);
  let connection; // 将 connection 移到 try-catch 外部，以便 finally 中访问
  try {
    connection = await pool.getConnection();
    console.log('[ARCHIVE_JOB_DB] Got DB connection.');

    // 1. 从热数据表中查询所有数据
    console.log('[ARCHIVE_JOB_DB] Querying all rows from GIS_devices_data_hot...');
    const [hotDataRows] = await connection.query('SELECT * FROM GIS_devices_data_hot');
    
    if (hotDataRows.length === 0) {
      console.log(`[ARCHIVE_JOB_INFO] Hot data table is empty. No archiving needed.`);
      connection.release(); // 别忘了释放连接
      return;
    }
    console.log(`[ARCHIVE_JOB_INFO] Found ${hotDataRows.length} rows to archive.`);

    // 2. 按 device_id 对数据进行分组
    const groupedData = hotDataRows.reduce((acc, row) => {
      const key = `device_${row.device_id}`;
      if (!acc[key]) { acc[key] = { deviceId: row.device_id, records: [] }; }
      acc[key].records.push(row);
      return acc;
    }, {});
    console.log(`[ARCHIVE_JOB_INFO] Grouped data into ${Object.keys(groupedData).length} device batches.`);

    // 3. 开启数据库事务
    await connection.beginTransaction();
    console.log('[ARCHIVE_JOB_DB] Transaction started.');

    // 4. 遍历每个分组
    for (const key in groupedData) {
      const group = groupedData[key];
      
      // 为设备查找对应的 user_id
      const [deviceMeta] = await connection.query('SELECT user_id FROM GIS_devices WHERE device_id = ?', [group.deviceId]);
      if (deviceMeta.length === 0) {
        console.warn(`[ARCHIVE_JOB_WARN] Cannot find user_id for device_id ${group.deviceId}. Skipping this group.`);
        continue; // 跳过这个设备的数据
      }
      const userId = deviceMeta[0].user_id;

      const jsonData = JSON.stringify(group.records, null, 2);
      
      // ==========================================================
      // 【【【 核心修改点在这里 (使用 dayjs 依赖库) 】】】
      // 使用 dayjs 获取当前的北京时间 ("Asia/Shanghai")，并格式化为文件名所需的部分。
      // 这种方法不依赖服务器的系统时区，更加可靠。
      const timestamp = dayjs().tz("Asia/Shanghai").format('YYYY-MM-DDTHH-mm-ss');
      const fileName = `${timestamp}_device_${group.deviceId}.json`;
      // ==========================================================
      
      const ossFolderPath = `GIS_数据冷处理备份/uploads_GIS_${userId}/`; // 使用动态获取的 userId
      const objectName = `${ossFolderPath}${fileName}`;

      // 4.1 上传到OSS
      console.log(`[ARCHIVE_JOB_OSS] Uploading to: ${objectName}`);
      await ossClient.put(objectName, Buffer.from(jsonData));
      const fileUrl = `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${objectName}`;
      console.log(`[ARCHIVE_JOB_OSS] Upload successful. URL: ${fileUrl}`);

      // 4.2 写入冷数据归档索引表
      const archiveTimestamp = new Date(group.records[0].record_time);
      const coldSql = 'INSERT INTO GIS_data_archives_2h (device_id, archive_timestamp, object_storage_url) VALUES (?, ?, ?)';
      const coldValues = [group.deviceId, archiveTimestamp, fileUrl];
      console.log('[ARCHIVE_JOB_DB] Inserting into cold archive table:', coldValues);
      await connection.query(coldSql, coldValues);
    }
    
    // 5. 删除热数据
    console.log('[ARCHIVE_JOB_DB] Deleting all rows from GIS_devices_data_hot...');
    await connection.query('DELETE FROM GIS_devices_data_hot');
    
    // 6. 提交事务
    await connection.commit();
    console.log(`[ARCHIVE_JOB_SUCCESS] Archiving successful. Transaction committed.`);

  } catch (error) {
    console.error(`[ARCHIVE_JOB_ERROR] Archiving failed. Rolling back transaction.`);
    console.error(error); // 打印完整错误信息
    if (connection) await connection.rollback(); // 只有在连接成功后才回滚
  } finally {
    if (connection) {
        connection.release();
        console.log('[ARCHIVE_JOB_DB] DB connection released.');
    }
  }
}

// cron表达式 '0 */2 * * *' 表示在每2个小时的0分执行
cron.schedule('0 */2 * * *', archiveHotData, {
  scheduled: true,
  timezone: "Asia/Shanghai"
});
console.log('数据归档定时任务已设置，每2小时执行一次。');

// 错误处理中间件
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('服务器内部错误');
});

// 启动服务器
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});