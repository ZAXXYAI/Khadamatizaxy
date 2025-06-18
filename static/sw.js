// استقبال الإشعار من السيرفر
self.addEventListener('push', function(event) {
  const data = event.data?.json() || {};
  const title = data.title || 'رسالة جديدة';
  const options = {
    body: data.body || 'لديك رسالة جديدة',
    icon: data.icon || '/static/images/notification-icon.png',
    badge: data.badge || '/static/images/badge.png',
    data: {
      url: data.url || '/'  // الرابط الذي يُفتح عند النقر
    }
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// التفاعل مع الإشعار (عند الضغط)
self.addEventListener('notificationclick', function(event) {
  event.notification.close();

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url === event.notification.data.url && 'focus' in client) {
          return client.focus();
        }
      }
      return clients.openWindow(event.notification.data.url);
    })
  );
});