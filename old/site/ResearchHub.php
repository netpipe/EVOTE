<?php
session_start();

// Database setup
$db = new SQLite3('ideas.db');
$db->exec("CREATE TABLE IF NOT EXISTS ideas (id INTEGER PRIMARY KEY, title TEXT, description TEXT, votes INTEGER DEFAULT 0)");
$db->exec("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)");
$db->exec("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, idea_id INTEGER, user_id TEXT, comment TEXT)");

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

// Handle commenting
if (isset($_POST['comment']) && isset($_SESSION['user']) && isset($_POST['idea_id'])) {
    $stmt = $db->prepare("INSERT INTO comments (idea_id, user_id, comment) VALUES (:idea_id, :user_id, :comment)");
    $stmt->bindValue(':idea_id', $_POST['idea_id']);
    $stmt->bindValue(':user_id', $_SESSION['user_id']);
    $stmt->bindValue(':comment', $_POST['comment']);
    $stmt->execute();
    header("Location: ?");
    exit();
}

// Search functionality
$searchQuery = isset($_GET['search']) ? $_GET['search'] : '';
$ideas = $db->query("SELECT * FROM ideas WHERE title LIKE '%$searchQuery%' OR description LIKE '%$searchQuery%' ORDER BY votes DESC");
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
    
        <h2>Search Ideas</h2>
        <form method="get">
            <input type="text" name="search" placeholder="Search for ideas" value="<?= htmlspecialchars($searchQuery) ?>">
            <button type="submit">Search</button>
        </form>
    
        <h2>Top Ideas</h2>
        <ul>
            <?php while ($row = $ideas->fetchArray()): ?>
                <li>
                    <strong><?= htmlspecialchars($row['title']) ?></strong> (<?= $row['votes'] ?> votes)
                    <br><?= htmlspecialchars($row['description']) ?>
                    <br><a href="?vote=<?= $row['id'] ?>">Vote</a>
                    
                    <h3>Comments</h3>
                    <ul>
                        <?php 
                        $comments = $db->query("SELECT * FROM comments WHERE idea_id = " . intval($row['id']));
                        while ($comment = $comments->fetchArray()): ?>
                            <li><?= htmlspecialchars($comment['comment']) ?></li>
                        <?php endwhile; ?>
                    </ul>
                    
                    <form method="post">
                        <input type="hidden" name="idea_id" value="<?= $row['id'] ?>">
                        <input type="text" name="comment" placeholder="Add a comment" required>
                        <button type="submit">Comment</button>
                    </form>
                </li>
            <?php endwhile; ?>
        </ul>
    <?php endif; ?>
</body>
</html>
