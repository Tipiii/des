from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import RegisterForm
from django.contrib.auth.forms import AuthenticationForm

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('send')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

from .models import Message
from .des_utils import encrypt_des, decrypt_des
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

@login_required
def send_view(request):
    users = User.objects.exclude(id=request.user.id)
    context = {"users": users}
    if request.method == 'POST':
        receiver_id = request.POST['receiver']
        message = request.POST['message']
        key = request.POST['key']

        receiver = User.objects.get(id=receiver_id)
        ciphertext = encrypt_des(message, key)

        Message.objects.create(
            sender=request.user,
            receiver=receiver,
            plaintext=message,
            ciphertext=ciphertext
        )
        context['success'] = 'Tin nhắn đã được mã hóa và gửi!'
    return render(request, 'send.html', context)

@login_required
def inbox_view(request):
    messages = Message.objects.filter(receiver=request.user).order_by('-created_at')
    context = {'messages': messages}

    if request.method == 'POST':
        msg_id = request.POST['msg_id']
        key = request.POST['key']
        msg = Message.objects.get(id=msg_id, receiver=request.user)
        try:
            decrypted = decrypt_des(msg.ciphertext, key)
            context['decrypted'] = decrypted
            context['decrypted_id'] = msg_id
        except:
            context['error'] = 'Giải mã thất bại (sai khóa)'
    return render(request, 'inbox.html', context)
