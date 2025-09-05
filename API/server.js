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




require('dotenv').config();

// 创建OSS客户端（放在路由定义之前）
const ossClient = new OSS({
  region: process.env.OSS_REGION,
  accessKeyId: process.env.ALIBABA_CLOUD_ACCESS_KEY_ID,
  accessKeySecret: process.env.ALIBABA_CLOUD_ACCESS_KEY_SECRET,
  bucket: process.env.OSS_BUCKET,
  secure: true // 强制HTTPS
});

const app = express();
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});



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


// 获取用户设备信息
app.get('/api/devices', async (req, res) => {
  try {
    const userId = req.query.user_id; // 从查询参数获取用户ID

    let query = `
      SELECT d.device_id, d.device_name, d.device_code, d.push_url, d.pull_url, 
             d.province, d.city, d.location, d.status, d.install_time,
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
app.post('/api/devices/:id/stream-url', async (req, res) => {
  const deviceId = req.params.id;
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
    push_url,
    pull_url,
    province,
    city,
    location,
    user_id,
    install_time
  } = req.body;

  // 1. 严格验证必填字段
  const requiredFields = [
    { name: 'device_name', value: device_name, msg: '设备类型不能为空' },
    { name: 'device_code', value: device_code, msg: '设备代码不能为空' },
    { name: 'user_id', value: user_id, msg: '所属用户ID不能为空' }
  ];
  for (const field of requiredFields) {
    if (!field.value) {
      return res.status(400).json({ error: field.msg });
    }
  }

  // 2. 字段格式验证
  if (device_name.length > 100) {
    return res.status(400).json({ error: '设备类型长度不能超过100字符' });
  }
  if (device_code.length > 20) {
    return res.status(400).json({ error: '设备代码长度不能超过20字符' });
  }

  try {
    // 3. 检查用户是否存在
    const [users] = await pool.query(
      'SELECT user_id FROM users WHERE user_id = ?',
      [user_id]
    );
    if (users.length === 0) {
      return res.status(404).json({ error: '所属用户不存在' });
    }

    // 4. 检查设备代码唯一性（数据库唯一约束）
    const [codeExists] = await pool.query(
      'SELECT device_id FROM devices WHERE device_code = ?',
      [device_code]
    );
    if (codeExists.length > 0) {
      return res.status(409).json({ error: '设备代码已被使用，请更换' });
    }


    const [result] = await pool.query(
      `INSERT INTO devices 
       (device_name, device_code, push_url, pull_url, province, city, location, user_id, install_time)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        device_name,
        device_code, // 必传，无需默认值
        push_url || null, // 可选字段，默认NULL
        pull_url || null, // 可选字段，默认NULL
        province || null,
        city || null,
        location || null,
        user_id,
        install_time ? new Date(install_time) : new Date() // 处理时间格式
      ]
    );

    // 7. 返回详细的成功响应
    res.status(201).json({
      success: true,
      message: '设备添加成功',
      data: {
        deviceId: result.insertId,
        device_code // 返回设备代码方便前端同步
      }
    });
  } catch (err) {
    console.error('添加设备失败:', err);
    // 区分数据库错误类型
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: '设备代码或流地址已存在（数据库约束）' });
    }
    res.status(500).json({
      error: '添加设备失败',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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
    pull_url
  } = req.body;

  // 1. 验证基础必填字段
  if (!device_name || device_code === undefined || status === undefined) {
    return res.status(400).json({ error: '设备类型、设备代码和状态为必填项' });
  }

  // 2. 验证设备ID合法性
  if (isNaN(Number(deviceId))) {
    return res.status(400).json({ error: '设备ID格式错误' });
  }

  try {
    // 3. 检查设备是否存在
    const [existingDevice] = await pool.query(
      'SELECT device_id, device_code FROM devices WHERE device_id = ?',
      [deviceId]
    );
    if (existingDevice.length === 0) {
      return res.status(404).json({ error: '目标设备不存在' });
    }
    const currentDevice = existingDevice[0];

    // 4. 若设备代码有变更，检查唯一性
    if (device_code !== currentDevice.device_code) {
      const [codeExists] = await pool.query(
        'SELECT device_id FROM devices WHERE device_code = ? AND device_id != ?',
        [device_code, deviceId] // 排除当前设备
      );
      if (codeExists.length > 0) {
        return res.status(409).json({ error: '设备代码已被其他设备使用' });
      }
    }

    // 5. 若流地址有变更，检查唯一性
    const urlChecks = [];
    for (const check of urlChecks) {
      const [urlExists] = await pool.query(
        `SELECT device_id FROM devices WHERE ${check.field} = ? AND device_id != ?`,
        [check.value, deviceId]
      );
      if (urlExists.length > 0) {
        return res.status(409).json({ error: check.msg });
      }
    }

    // 6. 执行更新操作（动态拼接更新字段，只更新传入的参数）
    const updateFields = [];
    const updateValues = [];

    updateFields.push('device_name = ?');
    updateValues.push(device_name);

    updateFields.push('device_code = ?');
    updateValues.push(device_code);

    updateFields.push('status = ?');
    updateValues.push(status);

    if (province !== undefined) updateFields.push('province = ?'), updateValues.push(province);
    if (city !== undefined) updateFields.push('city = ?'), updateValues.push(city);
    if (location !== undefined) updateFields.push('location = ?'), updateValues.push(location);
    if (push_url !== undefined) updateFields.push('push_url = ?'), updateValues.push(push_url);
    if (pull_url !== undefined) updateFields.push('pull_url = ?'), updateValues.push(pull_url);

    // 绑定设备ID
    updateValues.push(deviceId);

    const [result] = await pool.query(
      `UPDATE devices SET ${updateFields.join(', ')} WHERE device_id = ?`,
      updateValues
    );

    // 7. 返回更新结果
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '设备更新失败，未找到设备' });
    }

    res.json({
      success: true,
      message: '设备信息更新成功',
      data: { deviceId: Number(deviceId) }
    });
  } catch (err) {
    console.error('更新设备失败:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: '更新失败，设备代码或流地址重复' });
    }
    res.status(500).json({
      error: '更新设备失败',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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

// 修改后的OSS上传接口
app.post('/api/oss/upload', async (req, res) => {
  try {
    const { fileName, fileType } = req.body;

    // 生成唯一的文件名
    const objectName = `uploads/${Date.now()}_${fileName.replace(/\s+/g, '_')}`;

    // 生成带签名的上传URL
    const signedUrl = ossClient.signatureUrl(objectName, {
      method: 'PUT',
      'Content-Type': fileType,
      expires: 3600 // 1小时有效
    });

    // 生成访问URL
    const accessUrl = `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${objectName}`;

    res.json({
      signedUrl,
      accessUrl
    });
  } catch (err) {
    console.error('OSS上传错误:', err);
    res.status(500).json({
      error: '文件上传配置失败',
      details: err.message
    });
  }
});

// 替换现有的两个 /api/oss/files 路由为以下单个路由
app.get('/api/oss/files', async (req, res) => {
  try {
    // 获取目录参数，默认值为 'uploads/'
    let { directory = 'uploads/' } = req.query;

    // 确保目录以斜杠结尾
    if (!directory.endsWith('/')) {
      directory += '/';
    }

    // 对目录进行URL编码（确保特殊字符正确处理）
    const encodedDirectory = encodeURIComponent(directory).replace(/%2F/g, '/');

    // 列出指定目录下的所有文件
    const result = await ossClient.list({
      prefix: encodedDirectory,
      delimiter: '/',
      'max-keys': 1000
    });

    // 提取文件信息 - 处理URL中的%2F
    const files = (result.objects || []).map(file => ({
      name: file.name.replace(encodedDirectory, ''), // 移除目录前缀
      url: `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${file.name}`.replace(/%2F/g, '%252F'),
      lastModified: file.lastModified,
      size: file.size
    }));

    res.json(files);
  } catch (err) {
    console.error('获取OSS文件列表错误:', err);
    res.status(500).json({
      error: '获取文件列表失败',
      details: err.message
    });
  }
});



// 修改后的AI视觉检查接口（支持引发原因验证）
app.post('/api/ai-vision-check', async (req, res) => {
  try {
    const { images } = req.body; // 修改为接收图片数组，每个图片对象包含url和cause

    if (!images || !Array.isArray(images) || images.length === 0) {
      return res.status(400).json({ error: '缺少图片数据或格式不正确' });
    }

    // 辅助函数：判断是否为OSS上的图片
    const isOssImage = (url) => {
      return url.includes(`${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com`);
    };

    // 辅助函数：下载远程图片并返回Buffer
    const downloadImage = async (url) => {
      try {
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        return Buffer.from(response.data, 'binary');
      } catch (error) {
        console.error(`下载图片 ${url} 失败:`, error);
        throw new Error(`下载图片失败: ${error.message}`);
      }
    };

    const CAUSES_MAPPING = {
      '1': '声爆',
      '2': '烟火',
      '3': '异物入侵',
      '4': '飞鸟入侵',
      '5': '树木生长',
      '6': '异常放电',
      '7': '雷电侦测',
      '8': '大型车辆',
      '9': '杆塔倾斜',
      '10': '人员入侵',
      '11': '鸟巢',
      '12': '吊车',
      '13': '塔吊',
      '14': '翻斗车',
      '15': '推土机',
      '16': '水泥泵车',
      '17': '山火',
      '18': '烟雾',
      '19': '挖掘机',
      '20': '打桩机'
      // 可以继续添加其他映射关系
    };


    const results = await Promise.all(images.map(async (imageData) => {
      try {
        const { imageUrl, cause } = imageData;

        if (!imageUrl) {
          return {
            imageUrl: '',
            cause,
            error: '缺少图片URL',
            status: 'error'
          };
        }

        // 获取引发原因的中文描述
        const causeDescription = CAUSES_MAPPING[cause] || `未知原因(${cause})`;
        const causesArray = cause.split(',');
        const causeDescriptions = causesArray.map(c =>
          CAUSES_MAPPING[c.trim()] || `未知原因(${c.trim()})`
        ).join('、');

        // 调用火山引擎视觉模型
        const response = await axios.post(

          'https://ark.cn-beijing.volces.com/api/v3/chat/completions',
          {
            model: "doubao-1-5-thinking-vision-pro-250428",
            messages: [
              {
                "content": [
                  {
                    "image_url": { "url": imageUrl },
                    "type": "image_url"
                  },
                  {
                    "text": `请认真观察照片,这是摄像头拍摄识别的照片,框内为摄像头的判断内容,报警引发原因的:"${causeDescriptions}",这次报警是否判断正确？请只回答'是'或'否'。`,
                    "type": "text"
                  }
                ],
                "role": "user"
              }
            ]
          },
          {
            headers: {
              'Authorization': `Bearer ${process.env.AI_API_KEY}`,
              'Content-Type': 'application/json'
            }
          }
        );

        const aiResponse = response.data.choices?.[0]?.message?.content || "";
        const isAlarmValid = aiResponse.trim().toLowerCase() === "是";
        const targetFolder = isAlarmValid ? 'check_1/' : 'check_2/';

        console.log(`处理图片 ${imageUrl}，引发原因: ${causeDescription}，判断结果: ${isAlarmValid ? '正确' : '错误'}`);

        // 提取文件名（从URL中获取）
        const urlParts = imageUrl.split('/');
        let fileName = urlParts[urlParts.length - 1];

        // 处理可能的URL参数
        fileName = fileName.split('?')[0];

        const targetFileName = `${targetFolder}${fileName}`;
        let newUrl;

        try {
          if (isOssImage(imageUrl)) {
            // 如果是OSS上的图片，直接复制
            const originalFileName = `check/${fileName}`;
            await ossClient.copy(targetFileName, originalFileName);
            console.log(`[复制文件] 从 ${originalFileName} 复制到 ${targetFileName}`);
          } else {
            // 如果是外部图片，下载后上传到OSS
            const imageBuffer = await downloadImage(imageUrl);

            // 提取文件扩展名，设置正确的MIME类型
            const ext = fileName.split('.').pop()?.toLowerCase() || 'jpg';
            const contentType = ext === 'png' ? 'image/png' :
              ext === 'gif' ? 'image/gif' :
                'image/jpeg';

            await ossClient.put(targetFileName, imageBuffer, {
              headers: {
                'Content-Type': contentType
              }
            });
            console.log(`[上传文件] 从 ${imageUrl} 上传到 ${targetFileName}`);
          }

          // 生成新的图片URL
          newUrl = `https://${process.env.OSS_BUCKET}.${process.env.OSS_REGION}.aliyuncs.com/${targetFileName}`;

          return {
            imageUrl,
            cause,
            causeDescription,
            isAlarmValid,
            newUrl,
            status: 'success'
          };
        } catch (fileError) {
          console.error('文件处理失败:', fileError);
          return {
            imageUrl,
            cause,
            causeDescription,
            isAlarmValid,
            error: '文件处理失败',
            details: fileError.message,
            status: 'error'
          };
        }
      } catch (error) {
        console.error(`处理图片 ${imageData.imageUrl} 时出错:`, error);
        return {
          imageUrl: imageData.imageUrl,
          cause: imageData.cause,
          isAlarmValid: false,
          error: error.message,
          status: 'error'
        };
      }
    }));

    res.json({ results });

  } catch (error) {
    console.error('批量AI图像识别失败:', error);
    res.status(500).json({
      error: '批量AI图像识别失败',
      details: error.message
    });
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

// 创建报警信息接口
app.post('/api/alarm/create', async (req, res) => {
  try {
    const {
      causes,           // 危险类型（必填）
      level,            // 危险程度（必填）
      alarmImagePath,   // 照片位置（必填）
      deviceCode,       // 设备代码（必填）
      frameDistance = "[]",      // 默认值
      channelLocation = "定焦",  // 默认值
      aiResult = "{}",           // 默认值
      channel = "1"              // 默认值
    } = req.body;

    // 验证必填字段
    if (!causes || !level || !alarmImagePath || !deviceCode) {
      return res.status(400).json({
        error: '缺少必要参数',
        required: {
          causes: '危险类型',
          level: '危险程度',
          alarmImagePath: '照片位置',
          deviceCode: '设备代码'
        },
        received: req.body
      });
    }

    // 验证参数类型
    if (typeof level !== 'number') {
      return res.status(400).json({ error: 'level必须是数字' });
    }

    // 构建请求数据
    const requestData = {
      causes,
      level,
      alarmImagePath,
      deviceCode,
      frameDistance,
      channelLocation,
      aiResult,
      channel
    };

    console.log('发送报警创建请求:', requestData);

    // 调用原始接口
    const response = await axios.post(
      'http://47.104.136.74:20443/v1/alarm/create',
      requestData,
      {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000 // 10秒超时
      }
    );

    // 返回原始接口的响应
    res.json(response.data);

  } catch (error) {
    console.error('创建报警失败:', {
      error: error.message,
      requestData: req.body,
      apiError: error.response?.data
    });

    // 返回详细的错误信息
    res.status(error.response?.status || 500).json({
      error: '创建报警失败',
      details: error.response?.data || error.message,
      request: req.body
    });
  }
});


//新接口待添加



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

// 7. 删除报警错误照片//(成功)
app.post('/api/alarm/alarm', express.text({ type: ['text/plain'] }), express.json(), async (req, res) => {
  try {
    let requestBody;

    // 根据 Content-Type 处理不同的请求体格式
    if (req.is('text/plain')) {
      try {
        requestBody = JSON.parse(req.body);
      } catch (e) {
        return res.status(400).json({ error: '无效的JSON文本格式' });
      }
    } else if (req.is('application/json')) {
      requestBody = req.body;
    } else {
      return res.status(415).json({ error: '不支持的媒体类型，请使用 application/json 或 text/plain' });
    }

    const { id } = requestBody;

    const type = 4;
    const level = 1;
    const causes = "8";

    // 验证必填参数
    if (id === undefined) {
      return res.status(400).json({
        error: '缺少必要参数',
        required: {
          type: 'number',
          level: 'number',
          causes: 'string',
          id: 'number'
        },
        received: requestBody
      });
    }

    const response = await axios.post(
      'http://47.104.136.74:20443/v1/alarm/alarm',
      { type, level, causes, id },
      { headers: { 'Content-Type': 'application/json' } }
    );

    res.json(response.data);
  } catch (error) {
    console.error('删除报警错误照片失败:', {
      message: error.message,
      stack: error.stack,
      requestData: req.body,
      apiError: error.response?.data
    });

    res.status(error.response?.status || 500).json({
      error: '删除报警错误照片失败',
      details: error.response?.data || error.message
    });
  }
});















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