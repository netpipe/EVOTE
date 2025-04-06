<?php
session_start();

// Database setup
$db = new SQLite3('ideas.db');
$db->exec("CREATE TABLE IF NOT EXISTS ideas (id INTEGER PRIMARY KEY, title TEXT, description TEXT, votes INTEGER DEFAULT 0)");
$db->exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)");

// Facebook Login Integration (Replace with real credentials)
$fbAppId = 'YOUR_APP_ID';
$fbAppSecret = 'YOUR_APP_SECRET';
$redirectURL = 'YOUR_REDIRECT_URL';

if (isset($_GET['fb_login'])) {
    header("Location: https://www.facebook.com/v12.0/dialog/oauth?client_id=$fbAppId&redirect_uri=$redirectURL&scope=public_profile");
    exit();
}

if (isset($_GET['code'])) {
    $token = file_get_contents("https://graph.facebook.com/v12.0/oauth/access_token?client_id=$fbAppId&redirect_uri=$redirectURL&client_secret=$fbAppSecret&code=" . $_GET['code']);
    $user = json_decode(file_get_contents("https://graph.facebook.com/me?access_token=" . json_decode($token)->access_token));
    $_SESSION['user'] = $user->name;
    $_SESSION['user_id'] = $user->id;
    $db->exec("INSERT OR IGNORE INTO users (id, name) VALUES ('$user->id', '$user->name')");
    header("Location: ?");
    exit();
}

// Handle idea submission
if (isset($_POST['title']) && isset($_SESSION['user'])) {
    $stmt = $db->prepare("INSERT INTO ideas (title, description, votes) VALUES (:title, :description, 0)");
    $stmt->bindValue(':title', $_POST['title']);
    $stmt->bindValue(':description', $_POST['description']);
    $stmt->execute();
    header("Location: ?");
    exit();
}

// Handle voting
if (isset($_GET['vote']) && isset($_SESSION['user'])) {
    $db->exec("UPDATE ideas SET votes = votes + 1 WHERE id = " . intval($_GET['vote']));
    header("Location: ?");
    exit();
}

// Fetch ideas
$ideas = $db->query("SELECT * FROM ideas ORDER BY votes DESC");
?>
<!DOCTYPE html>
<html>
<head>
    <title>Open Research Hub</title>
</head>
<body>
    <h1>Open Research Hub</h1>
    
    <?php if (!isset($_SESSION['user'])): ?>
        <a href="?fb_login=1">Login with Facebook</a>
    <?php else: ?>
        <p>Welcome, <?= $_SESSION['user'] ?>! <a href="?logout=1">Logout</a></p>
    
        <h2>Submit a New Idea</h2>
        <form method="post">
            <input type="text" name="title" placeholder="Idea title" required>
            <textarea name="description" placeholder="Describe your idea" required></textarea>
            <button type="submit">Submit</button>
        </form>
    
        <h2>Top Ideas</h2>
        <ul>
            <?php while ($row = $ideas->fetchArray()): ?>
                <li>
                    <strong><?= htmlspecialchars($row['title']) ?></strong> (<?= $row['votes'] ?> votes)
                    <br><?= htmlspecialchars($row['description']) ?>
                    <br><a href="?vote=<?= $row['id'] ?>">Vote</a>
                </li>
            <?php endwhile; ?>
        </ul>
    <?php endif; ?>
</body>
</html>
