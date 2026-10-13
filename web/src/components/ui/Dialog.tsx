import React from 'react';
import { Modal } from './Modal';
import { Button } from './Button';
import { ExclamationTriangleIcon, InformationCircleIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { clsx } from 'clsx';

export interface DialogProps {
    isOpen: boolean;
    onClose: () => void;
    title: string;
    message: string;
    type?: 'info' | 'warning' | 'success' | 'danger';
    confirmText?: string;
    cancelText?: string;
    onConfirm?: () => void;
    onCancel?: () => void;
    loading?: boolean;
    showCancel?: boolean;
}

const Dialog: React.FC<DialogProps> = ({
    isOpen,
    onClose,
    title,
    message,
    type = 'info',
    confirmText = 'OK',
    cancelText = 'Cancel',
    onConfirm,
    onCancel,
    loading = false,
    showCancel = true,
}) => {
    const handleConfirm = () => {
        if (onConfirm) {
            onConfirm();
        } else {
            onClose();
        }
    };

    const handleCancel = () => {
        if (onCancel) {
            onCancel();
        } else {
            onClose();
        }
    };

    const iconConfig = {
        info: {
            icon: InformationCircleIcon,
            bgColor: 'bg-blue-100',
            iconColor: 'text-blue-600',
        },
        warning: {
            icon: ExclamationTriangleIcon,
            bgColor: 'bg-yellow-100',
            iconColor: 'text-yellow-600',
        },
        success: {
            icon: CheckCircleIcon,
            bgColor: 'bg-green-100',
            iconColor: 'text-green-600',
        },
        danger: {
            icon: ExclamationTriangleIcon,
            bgColor: 'bg-red-100',
            iconColor: 'text-red-600',
        },
    };

    const config = iconConfig[type];
    const Icon = config.icon;

    const confirmButtonVariant = type === 'danger' ? 'destructive' : 'default';

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title={title}
            hideTitleVisually
            size="sm"
            showCloseButton={false}
            closeOnOverlayClick={!loading}
        >
            <div className="flex">
                <div
                    className={clsx(
                        'mx-auto flex h-12 w-12 shrink-0 items-center justify-center rounded-full',
                        config.bgColor
                    )}
                >
                    <Icon className={clsx('h-6 w-6', config.iconColor)} aria-hidden="true" />
                </div>
                <div className="ml-4 text-left">
                    <h3 className="text-lg font-medium text-base-primary">{title}</h3>
                    <div className="mt-2">
                        <p className="text-sm text-base-secondary">{message}</p>
                    </div>
                </div>
            </div>

            <div className="mt-6 flex justify-end space-x-3">
                {showCancel && (
                    <Button variant="outline" onClick={handleCancel} disabled={loading}>
                        {cancelText}
                    </Button>
                )}
                <Button variant={confirmButtonVariant} onClick={handleConfirm} loading={loading}>
                    {confirmText}
                </Button>
            </div>
        </Modal>
    );
};

export { Dialog };
