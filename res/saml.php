<!DOCTYPE html>

<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SAML Information</title>
  <style>
  table {
      border-collapse: collapse;
      border: 1px solid #ccc;
  }

  tbody tr:nth-child(2n+1) td, tbody tr:nth-child(2n+1) th {
      background-color: rgb(235, 235, 235);
  }

  td, th {
      padding: 5px;
      vertical-align: top;
  }
  </style>
</head>
<body>

<h1>SAML information</h1>
<?php
    require_once('{INSTALL_DIR}/ssp/sp/lib/_autoload.php');
    $as = new SimpleSAML_Auth_Simple('default-sp');
    $as->requireAuth();
?>

<h2>NameID</h2>
<table>
<thead>
<tr><th>Key</th><th>Value</th></tr>
</thead>
<tbody>
<?php
foreach ($as->getAuthData("saml:sp:NameID") as $k => $v) {
?>
    <tr><td><strong><?php echo $k; ?></strong></td><td><?php echo $v; ?></td></tr>
<?php
}
?>
</tbody>
</table>

<h2>IdP</h2>
<?php print_r($as->getAuthData("saml:sp:IdP")); ?>

<h2>Authenticating Authority</h2>
<table>
<thead>
<tr><th>Index</th><th>IdP</th></tr>
</thead>
<tbody>
<?php
foreach ($as->getAuthData('saml:AuthenticatingAuthority') as $k => $v) {
?>
    <tr><td><strong><?php echo $k; ?></strong></td><td><?php echo $v; ?></td></tr>
<?php
}
?>
</tbody>
</table>

<h2>SessionIndex</h2>
<?php print_r($as->getAuthData("saml:sp:SessionIndex")); ?>

<h2>Attributes</h2>
<table>
<thead>
<tr><th>Attribute</th><th>Value</th></tr>
</thead>
<tbody>
<?php
foreach ($as->getAttributes() as $k => $v) {
?>
    <tr><td><strong><?php echo $k; ?></strong></td><td><?php echo implode("<br>", $v); ?></td></tr>
<?php
}
?>
</tbody>
</table>
</body>
</html>
