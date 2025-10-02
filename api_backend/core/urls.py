from django.urls import path, include
from rest_framework_nested import routers

from .views import (
    BlockViewSet,
    TransactionViewSet,
    WalletViewSet,
    WalletAddressViewSet,
    WalletTransactViewSet,
)

# Main router
router = routers.SimpleRouter()
router.register(r'blocks', BlockViewSet, basename='block')
router.register(r'transactions', TransactionViewSet, basename='transaction')
router.register(r'wallets', WalletViewSet, basename='wallet')

# Nested: /blocks/{height}/transactions/
blocks_router = routers.NestedSimpleRouter(router, r'blocks', lookup='block')
blocks_router.register(r'transactions', TransactionViewSet, basename='block-transactions')

# Nested: /wallets/{id}/addresses/
wallets_router = routers.NestedSimpleRouter(router, r'wallets', lookup='wallet')
wallets_router.register(r'addresses', WalletAddressViewSet, basename='wallet-address')
wallets_router.register(r'transact', WalletTransactViewSet, basename='wallet-transact')

urlpatterns = [
    path("", include(router.urls)),
    path("", include(blocks_router.urls)),
    path("", include(wallets_router.urls)),
]
