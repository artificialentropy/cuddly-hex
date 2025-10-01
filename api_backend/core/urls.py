from rest_framework.routers import DefaultRouter
from .views import WalletViewSet, AssetViewSet, TransactionViewSet

router = DefaultRouter()
router.register(r"wallets", WalletViewSet, basename="wallet")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"transactions", TransactionViewSet, basename="transaction")

urlpatterns = router.urls
