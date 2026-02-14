#!/bin/bash

echo "================================================"
echo "   🚀 سكريبت رفع المشروع على GitHub"
echo "================================================"
echo ""

# التحقق من وجود Git
if ! command -v git &> /dev/null; then
    echo "❌ Git غير مثبت على جهازك!"
    echo "   قم بتحميله من: https://git-scm.com/downloads"
    exit 1
fi

echo "✅ Git مثبت بنجاح"
echo ""

# طلب معلومات GitHub من المستخدم
echo "📝 الرجاء إدخال المعلومات التالية:"
echo ""

read -p "اسم المستخدم على GitHub: " GITHUB_USERNAME
read -p "اسم المستودع (Repository name): " REPO_NAME

echo ""
echo "================================================"
echo "   📤 جاري رفع المشروع..."
echo "================================================"
echo ""

# إضافة remote
git remote remove origin 2>/dev/null
git remote add origin "https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git"

echo "✅ تم ربط المشروع بـ GitHub"
echo ""

# رفع الكود
echo "📤 جاري رفع الملفات..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "================================================"
    echo "   ✅ تم رفع المشروع بنجاح!"
    echo "================================================"
    echo ""
    echo "🔗 رابط المستودع:"
    echo "   https://github.com/${GITHUB_USERNAME}/${REPO_NAME}"
    echo ""
    echo "📋 الخطوة التالية:"
    echo "   - انتقل إلى Back4App: https://www.back4app.com"
    echo "   - أنشئ تطبيق جديد واختر 'Deploy from GitHub'"
    echo "   - اختر المستودع: ${REPO_NAME}"
    echo "   - اتبع التعليمات في ملف DEPLOYMENT_GUIDE.md"
    echo ""
else
    echo ""
    echo "❌ حدث خطأ أثناء الرفع!"
    echo ""
    echo "💡 تأكد من:"
    echo "   1. إنشاء المستودع على GitHub أولاً"
    echo "   2. استخدام Personal Access Token بدلاً من كلمة المرور"
    echo "   3. منح الصلاحيات المناسبة للـ Token"
    echo ""
    echo "📖 لإنشاء Token:"
    echo "   GitHub → Settings → Developer settings → Personal access tokens → Generate new token"
    echo ""
fi
