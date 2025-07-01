<?php
$data_dir = '/var/www/top_ips/data';

// Получаем список JSON файлов с датами
$dates = [];
if (is_dir($data_dir)) {
    $files = scandir($data_dir);
    foreach ($files as $file) {
        if (preg_match('/^\d{4}-\d{2}-\d{2}\.json$/', $file)) {
            $dates[] = substr($file, 0, 10);
        }
    }
}
sort($dates);

function valid_date($date) {
    $d = DateTime::createFromFormat('Y-m-d', $date);
    return $d && $d->format('Y-m-d') === $date;
}

$start_date = isset($_GET['start_date']) && valid_date($_GET['start_date']) ? $_GET['start_date'] : ($dates[0] ?? null);
$end_date = isset($_GET['end_date']) && valid_date($_GET['end_date']) ? $_GET['end_date'] : ($dates[count($dates)-1] ?? null);

if ($start_date && $end_date && $start_date > $end_date) {
    list($start_date, $end_date) = [$end_date, $start_date];
}

$results = null;

if ($start_date && $end_date) {
    $selected_dates = array_filter($dates, function($d) use ($start_date, $end_date) {
        return $d >= $start_date && $d <= $end_date;
    });

    $combined = [];
    foreach ($selected_dates as $date) {
        $json_file = $data_dir . DIRECTORY_SEPARATOR . $date . '.json';
        if (file_exists($json_file)) {
            $content = file_get_contents($json_file);
            $data = json_decode($content, true);
            if ($data !== null) {
                foreach ($data as $prefix => $rows) {
                    if (!isset($combined[$prefix])) {
                        $combined[$prefix] = [];
                    }
                    foreach ($rows as $row) {
                        $ip = $row['ip'];
                        if (!isset($combined[$prefix][$ip])) {
                            $combined[$prefix][$ip] = [
                                'ip' => $ip,
                                'count' => 0,
                                'country' => $row['country'],
                                'netname' => $row['netname'],
                                'description' => $row['description'],
                            ];
                        }
                        $combined[$prefix][$ip]['count'] += $row['count'];
                    }
                }
            }
        }
    }

    $results = [];
    foreach ($combined as $prefix => $ips) {
        usort($ips, function($a, $b) {
            return $b['count'] <=> $a['count'];
        });
        $results[$prefix] = $ips;
    }
}

function h($s) {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}

// Иконка лупы (search)
function icon_search() {
    return '<svg aria-label="Search" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" stroke="#007bff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>';
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8" />
<title>Просмотр IP-отчётов по диапазону дат</title>
<style>
  table, th, td { border:1px solid #aaa; border-collapse: collapse; padding: 4px; }
  th { background: #eee; }
  form > label { margin-right: 10px; }
  td.link-icon a {
    display: inline-block;
    vertical-align: middle;
    text-decoration: none;
  }
  td.link-icon a svg {
    width: 18px;
    height: 18px;
    stroke-width: 2;
    transition: stroke 0.3s;
  }
  td.link-icon a:hover svg {
    stroke-width: 3;
  }
</style>
</head>
<body>
  <h1>Выбор диапазона дат</h1>
  <?php if (count($dates) > 0): ?>
    <form method="get">
      <label>
        С даты:
        <select name="start_date">
          <?php foreach ($dates as $date): ?>
            <option value="<?=h($date)?>" <?= $date === $start_date ? 'selected' : '' ?>><?=h($date)?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <label>
        По дату:
        <select name="end_date">
          <?php foreach ($dates as $date): ?>
            <option value="<?=h($date)?>" <?= $date === $end_date ? 'selected' : '' ?>><?=h($date)?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <button type="submit">Показать</button>
    </form>
  <?php else: ?>
    <p>Нет доступных отчетов для выбора.</p>
  <?php endif; ?>

<?php if ($results): ?>
  <?php foreach ($results as $prefix => $rows): ?>
    <h2><?=h($prefix)?></h2>
    <?php if (empty($rows)): ?>
      <p>Нет данных</p>
    <?php else: ?>
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Count</th>
            <th>Country</th>
            <th>Netname</th>
            <th>Description</th>
            <th>Whois</th>
            <th>VirusTotal</th>
            <th>Shodan</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($rows as $row): ?>
            <tr>
              <td><?= h($row['ip']) ?></td>
              <td><?= h($row['count']) ?></td>
              <td><?= h($row['country']) ?></td>
              <td><?= h($row['netname']) ?></td>
              <td><?= h($row['description']) ?></td>
              <td class="link-icon">
                <a href="https://whois.com/whois/<?= urlencode($row['ip']) ?>" target="_blank" rel="noopener noreferrer" title="Whois">
                  <?= icon_search() ?>
                </a>
              </td>
              <td class="link-icon">
                <a href="https://www.virustotal.com/gui/ip-address/<?= urlencode($row['ip']) ?>" target="_blank" rel="noopener noreferrer" title="VirusTotal">
                  <?= icon_search() ?>
                </a>
              </td>
              <td class="link-icon">
                <a href="https://www.shodan.io/search?query=<?= urlencode($row['ip']) ?>" target="_blank" rel="noopener noreferrer" title="Shodan">
                  <?= icon_search() ?>
                </a>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  <?php endforeach; ?>
<?php endif; ?>

</body>
</html>
